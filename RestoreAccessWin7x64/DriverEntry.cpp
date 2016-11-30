#include <ntddk.h>  


extern "C" NTKERNELAPI PVOID NTAPI
ObGetObjectType(
	IN PVOID pObject
);

extern "C" NTKERNELAPI UCHAR*
PsGetProcessImageFileName(
	IN PEPROCESS Process
);


extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
	__in HANDLE ProcessId,
	__deref_out PEPROCESS *Process
);

#define   MAX_ENTRY_COUNT (0x1000/16)  //一级表中的 HANDLE_TABLE_ENTRY个数  
#define   MAX_ADDR_COUNT   (0x1000/8) //二级表和 三级表中的地址个数  
#define	  HANDLE_TABLE_OFFSET_WIN7X64 0x200

ULONG g_ProcessCount = 0;


typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof)   
{
	union                                    // 3 elements, 0x8 bytes (sizeof)   
	{
		struct                               // 5 elements, 0x8 bytes (sizeof)   
		{
			/*0x000*/             UINT64       Locked : 1;         // 0 BitPosition                    
			/*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition                    
			/*0x000*/             UINT64       Waking : 1;         // 2 BitPosition                    
			/*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition                    
			/*0x000*/             UINT64       Shared : 60;        // 4 BitPosition                    
		};
		/*0x000*/         UINT64       Value;
		/*0x000*/         VOID*        Ptr;
	};
}EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef struct _HANDLE_TRACE_DB_ENTRY // 4 elements, 0xA0 bytes (sizeof)   
{
	/*0x000*/     struct _CLIENT_ID ClientId;       // 2 elements, 0x10 bytes (sizeof)   
	/*0x010*/     VOID*        Handle;
	/*0x018*/     ULONG32      Type;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
	/*0x020*/     VOID*        StackTrace[16];
}HANDLE_TRACE_DB_ENTRY, *PHANDLE_TRACE_DB_ENTRY;



typedef struct _HANDLE_TRACE_DEBUG_INFO       // 6 elements, 0xF0 bytes (sizeof)   
{
	/*0x000*/     LONG32       RefCount;
	/*0x004*/     ULONG32      TableSize;
	/*0x008*/     ULONG32      BitMaskFlags;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
	/*0x010*/     struct _FAST_MUTEX CloseCompactionLock;   // 5 elements, 0x38 bytes (sizeof)   
	/*0x048*/     ULONG32      CurrentStackIndex;
	/*0x04C*/     UINT8        _PADDING1_[0x4];
	/*0x050*/     struct _HANDLE_TRACE_DB_ENTRY TraceDb[];
}HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;


typedef struct _HANDLE_TABLE_ENTRY                  // 8 elements, 0x10 bytes (sizeof)   
{
	union                                           // 4 elements, 0x8 bytes (sizeof)    
	{
		/*0x000*/         VOID*        Object;
		/*0x000*/         ULONG32      ObAttributes;
		/*0x000*/         struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;
		/*0x000*/         UINT64       Value;
	};
	union                                           // 3 elements, 0x8 bytes (sizeof)    
	{
		/*0x008*/         ULONG32      GrantedAccess;
		struct                                      // 2 elements, 0x8 bytes (sizeof)    
		{
			/*0x008*/             UINT16       GrantedAccessIndex;
			/*0x00A*/             UINT16       CreatorBackTraceIndex;
			/*0x00C*/             UINT8        _PADDING0_[0x4];
		};
		/*0x008*/         ULONG32      NextFreeTableEntry;
	};
}HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

/*
0: kd> dt _HANDLE_TABLE_ENTRY
nt!_HANDLE_TABLE_ENTRY
+0x000 Object           : Ptr64 Void
+0x000 ObAttributes     : Uint4B
+0x000 InfoTable        : Ptr64 _HANDLE_TABLE_ENTRY_INFO
+0x000 Value            : Uint8B
+0x008 GrantedAccess    : Uint4B
+0x008 GrantedAccessIndex : Uint2B
+0x00a CreatorBackTraceIndex : Uint2B
+0x008 NextFreeTableEntry : Uint4B

*/



typedef struct _HANDLE_TABLE
{
	ULONG64 TableCode;
	PEPROCESS QuotaProcess;
	PVOID UniqueProcessId;
	EX_PUSH_LOCK HandleLock;
	LIST_ENTRY HandleTableList;
	EX_PUSH_LOCK HandleContentionEvent;
	PHANDLE_TRACE_DEBUG_INFO DebugInfo;
	LONG ExtraInfoPages;
	ULONG Flags;
	//ULONG StrictFIFO : 1;  
	LONG64 FirstFreeHandle;
	PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
	LONG HandleCount;
	ULONG NextHandleNeedingPool;
} HANDLE_TABLE, *PHANDLE_TABLE;


typedef BOOLEAN(*MY_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter);

SIZE_T FindCidTable()
{
	SIZE_T  CidTableAddr = 0;
	UNICODE_STRING ustPsFuncName;
	RtlInitUnicodeString(&ustPsFuncName, L"PsLookupProcessByProcessId");
	PUCHAR startAddr = (PUCHAR)MmGetSystemRoutineAddress(&ustPsFuncName);

	for (ULONG64 i = 0; i < 100; i++)
	{
		if (*(startAddr + i) == 0x48 &&
			*(startAddr + i + 1) == 0x8b &&
			*(startAddr + i + 2) == 0x0d)
		{
			CidTableAddr = (SIZE_T)(*(PULONG)(startAddr + i + 3) + (startAddr + i + 3 + 4)) & 0xFFFFFFFEFFFFFFFF;
			DbgPrint("CidTableAddr:%p\n", CidTableAddr);
			break;
		}
	}
	return CidTableAddr;
}


BOOLEAN MyEnumerateHandleRoutine(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
)
{
	BOOLEAN Result = FALSE;
	ULONG64 ProcessObject = 0;
	POBJECT_TYPE ObjectType = NULL;
	PVOID Object = NULL;
	ULONG32 Access = 0;
	UNICODE_STRING ustObjectName;

	UNREFERENCED_PARAMETER(EnumParameter);
	UNREFERENCED_PARAMETER(ustObjectName);
	ProcessObject = (HandleTableEntry->Value)&~7; //掩去低三位  
	Object = (PVOID)((ULONG64)HandleTableEntry->Object&~7);
	if (Object == NULL)
		return FALSE;

	ProcessObject += (ULONG64)0x30;
	Access = HandleTableEntry->GrantedAccess;

	ObjectType = (POBJECT_TYPE)ObGetObjectType((PVOID)ProcessObject);
	if (MmIsAddressValid(HandleTableEntry))
	{
		//if (ObjectType == *PsProcessType)//判断是否为Process  
		//{
		//	//注意PID其实就是Handle,而 不是从EPROCESS中取,可以对付伪pid  
		//	g_ProcessCount++;
		//	DbgPrint("PID=%4d\t EPROCESS=0x%p %s\n", Handle, ProcessObject, PsGetProcessImageFileName((PEPROCESS)ProcessObject));
		//}
		if (ObjectType == NULL)
			return FALSE;

		DbgPrint("0x%x - 0x%x - 0x%llx - %ws \n", Handle, Access, ProcessObject, *(PCWSTR*)((PUCHAR)ObjectType + 0x18));
	}

	return Result;//返回FALSE继续  
}


//自己实现一个山寨的MyEnumHandleTable,接口和ExEnumHandleTable一样  
BOOLEAN
MyEnumHandleTable(
	PHANDLE_TABLE HandleTable,
	MY_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	PVOID EnumParameter,
	PHANDLE Handle
)
{
	ULONG64 i, j, k;
	ULONG_PTR CapturedTable;
	ULONG64 TableLevel;
	PHANDLE_TABLE_ENTRY TableLevel1, *TableLevel2, **TableLevel3;
	BOOLEAN CallBackRetned = FALSE;
	BOOLEAN ResultValue = FALSE;
	ULONG64 MaxHandle;
	//判断几个参数是否有效  
	if (!HandleTable
		&& !EnumHandleProcedure
		&& !MmIsAddressValid(Handle))
	{
		return ResultValue;
	}
	//取表基址和表的级数  
	CapturedTable = (HandleTable->TableCode)&~3;
	TableLevel = (HandleTable->TableCode) & 3;
	MaxHandle = HandleTable->NextHandleNeedingPool;
	DbgPrint("句柄上限值为0x%X\n", MaxHandle);
	//判断表的等级  
	switch (TableLevel)
	{
	case 0:
	{
		//一级表  
		TableLevel1 = (PHANDLE_TABLE_ENTRY)CapturedTable;
		DbgPrint("解析一级表 0x%p...\n", TableLevel1);
		for (i = 0; i < MAX_ENTRY_COUNT; i++)
		{
			*Handle = (HANDLE)(i * 4);
			if (TableLevel1[i].Object && MmIsAddressValid(TableLevel1[i].Object))
			{
				//对象有效时，再调用回调函数  
				CallBackRetned = EnumHandleProcedure(&TableLevel1[i], *Handle, EnumParameter);
				if (CallBackRetned)  break;
			}
		}
		ResultValue = TRUE;

	}
	break;
	case 1:
	{
		//二级表  
		TableLevel2 = (PHANDLE_TABLE_ENTRY*)CapturedTable;
		DbgPrint("解析二级表 0x%p...\n", TableLevel2);
		DbgPrint("二级表的个 数:%d\n", MaxHandle / (MAX_ENTRY_COUNT * 4));
		for (j = 0; j < MaxHandle / (MAX_ENTRY_COUNT * 4); j++)
		{
			TableLevel1 = TableLevel2[j];
			if (!TableLevel1)
				break; //为零则跳出  
			for (i = 0; i < MAX_ENTRY_COUNT; i++)
			{
				*Handle = (HANDLE)(j*MAX_ENTRY_COUNT * 4 + i * 4);
				if (TableLevel1[i].Object && MmIsAddressValid(TableLevel1[i].Object))
				{
					//对象有效时，再调用回调函数  
					CallBackRetned = EnumHandleProcedure(&TableLevel1[i], *Handle, EnumParameter);
					if (CallBackRetned)  break;
				}
			}
		}
		ResultValue = TRUE;
	}
	break;
	case 2:
	{
		//三级表  
		TableLevel3 = (PHANDLE_TABLE_ENTRY**)CapturedTable;
		DbgPrint("解析三级表 0x%p...\n", TableLevel3);
		DbgPrint("三级表的个 数:%d\n", MaxHandle / (MAX_ENTRY_COUNT * 4 * MAX_ADDR_COUNT));
		for (k = 0; k < MaxHandle / (MAX_ENTRY_COUNT * 4 * MAX_ADDR_COUNT); k++)
		{
			TableLevel2 = TableLevel3[k];
			if (!TableLevel2)
				break; //为零则跳出  
			for (j = 0; j < MaxHandle / (MAX_ENTRY_COUNT * 4); j++)
			{
				TableLevel1 = TableLevel2[j];
				if (!TableLevel1)
					break; //为零则跳出  
				for (i = 0; i < MAX_ENTRY_COUNT; i++)
				{
					*Handle = (HANDLE)(k*MAX_ENTRY_COUNT*MAX_ADDR_COUNT + j*MAX_ENTRY_COUNT + i * 4);
					if (TableLevel1[i].Object && MmIsAddressValid(TableLevel1[i].Object))
					{
						//对象有效时，再调用回调函数  
						CallBackRetned = EnumHandleProcedure(&TableLevel1[i], *Handle, EnumParameter);
						if (CallBackRetned)  break;
					}
				}
			}
		}
		ResultValue = TRUE;
	}
	break;
	default:
	{
		DbgPrint("BOOM!\n");
	}
	break;
	}
	DbgPrint("ProcessCount:0x%x", g_ProcessCount);
	return ResultValue;
}


void EnumProcessHandle(HANDLE pid)
{
	HANDLE hHanel;
	PEPROCESS Process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &Process)))
		return;
	
	MyEnumHandleTable(*(PHANDLE_TABLE*)((PUCHAR)Process + HANDLE_TABLE_OFFSET_WIN7X64), MyEnumerateHandleRoutine, NULL, &hHanel);
	ObDereferenceObject(Process);
}

void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	DbgPrint("GoodBye!\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);

	pDriverObject->DriverUnload = DriverUnload;

	DbgPrint("DriverEntry!\n");

	EnumProcessHandle((HANDLE)1452);

	return STATUS_SUCCESS;
}