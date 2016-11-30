#include <ntddk.h>
#include "RestoreAccess.h"

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(
	IN PHANDLE_TABLE HandleTable,
	IN EXHANDLE tHandle
)
{
	ULONG_PTR i, j, k;
	ULONG_PTR CapturedTable;
	ULONG TableLevel;
	PHANDLE_TABLE_ENTRY Entry = NULL;
	EXHANDLE Handle;

	PUCHAR TableLevel1;
	PUCHAR TableLevel2;
	PUCHAR TableLevel3;

	ULONG_PTR MaxHandle;

	PAGED_CODE();

	Handle = tHandle;
	Handle.TagBits = 0;

	MaxHandle = *(volatile ULONG *)&HandleTable->NextHandleNeedingPool;
	if (Handle.Value >= MaxHandle)
	{
		return NULL;
	}

	CapturedTable = *(volatile ULONG_PTR *)&HandleTable->TableCode;
	TableLevel = (ULONG)(CapturedTable & LEVEL_CODE_MASK);
	CapturedTable = CapturedTable - TableLevel;

	switch (TableLevel)
	{
	case 0:
	{
		TableLevel1 = (PUCHAR)CapturedTable;

		Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[Handle.Value *
			(sizeof(HANDLE_TABLE_ENTRY) / HANDLE_VALUE_INC)];

		break;
	}

	case 1:
	{
		TableLevel2 = (PUCHAR)CapturedTable;

		i = Handle.Value % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);
		Handle.Value -= i;
		j = Handle.Value / ((LOWLEVEL_COUNT * HANDLE_VALUE_INC) / sizeof(PHANDLE_TABLE_ENTRY));

		TableLevel1 = (PUCHAR)*(PHANDLE_TABLE_ENTRY*)&TableLevel2[j];
		Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[i * (sizeof(HANDLE_TABLE_ENTRY) / HANDLE_VALUE_INC)];

		break;
	}

	case 2:
	{
		TableLevel3 = (PUCHAR)CapturedTable;

		i = Handle.Value % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);
		Handle.Value -= i;
		k = Handle.Value / ((LOWLEVEL_COUNT * HANDLE_VALUE_INC) / sizeof(PHANDLE_TABLE_ENTRY));
		j = k % (MIDLEVEL_COUNT * sizeof(PHANDLE_TABLE_ENTRY));
		k -= j;
		k /= MIDLEVEL_COUNT;

		TableLevel2 = (PUCHAR)*(PHANDLE_TABLE_ENTRY*)&TableLevel3[k];
		TableLevel1 = (PUCHAR)*(PHANDLE_TABLE_ENTRY*)&TableLevel2[j];
		Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[i * (sizeof(HANDLE_TABLE_ENTRY) / HANDLE_VALUE_INC)];

		break;
	}

	default: _assume(0);
	}

	return Entry;
}


////////////////////////////////////////////////////////////////////////////////////////////////////

/*
RestoreObjectAccess : 恢复被ObRegistrCallBacks修改了权限的进程
参数:
ActiveId:要恢复的进程id(不是游戏进程)
PassiveId:被保护的进程id(游戏进程)
*/
NTSTATUS RestoreObjectAccess(ULONG32 ActiveId, ULONG32 PassiveId)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS EProcess = NULL;
	ULONG_PTR Handle = 0;
	PHANDLE_TABLE_ENTRY Entry = NULL;
	POBJECT_TYPE ObjectType = NULL;
	ULONG64 Object = 0;

	DbgPrint("RestoreObjectAccess :%d -- %d\n", ActiveId, PassiveId);
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ActiveId, &EProcess)))
	{
		return Status;
	}

	for (Handle = 0;; Handle += HANDLE_VALUE_INC)
	{
		Entry = ExpLookupHandleTableEntry(*(PHANDLE_TABLE*)((PUCHAR)EProcess + HANDLE_TABLE_OFFSET_WIN7), *(PEXHANDLE)&Handle);
		if (Entry == NULL)
		{
			break;
		}

		Object = (Entry->Value)&~7;

		if (Object == 0)
		{
			continue;
		}

		Object += (ULONG64)0x30;

		ObjectType = (POBJECT_TYPE)ObGetObjectType((PVOID)Object);

		if (ObjectType == NULL)
		{
			continue;
		}

		/*
		0: kd> dt _object_type ffffe001796529e0
		nt!_OBJECT_TYPE
		+0x000 TypeList         : _LIST_ENTRY [ 0xffffe001`796529e0 - 0xffffe001`796529e0 ]
		+0x010 Name             : _UNICODE_STRING "Process"
		+0x020 DefaultObject    : (null)
		+0x028 Index            : 0x7 ''
		+0x02c TotalNumberOfObjects : 0x2f
		+0x030 TotalNumberOfHandles : 0x136
		+0x034 HighWaterNumberOfObjects : 0x37
		+0x038 HighWaterNumberOfHandles : 0x16e
		+0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
		+0x0b8 TypeLock         : _EX_PUSH_LOCK
		+0x0c0 Key              : 0x636f7250
		+0x0c8 CallbackList     : _LIST_ENTRY [ 0xffffc001`32861d40 - 0xffffc001`32861d40 ]

		0x18
		0: kd> dpu ffffe001796529e0+0x18
		ffffe001`796529f8  ffffc001`31c16990 "Process"
		ffffe001`79652a00  00000000`00000000
		ffffe001`79652a08  0000002f`4b424707

		*/
		if (ObjectType == *PsProcessType)
		{
			//DbgPrint("0x%x - 0x%x - 0x%llx - %ws \n", Handle, Entry->GrantedAccess, Object, *(PCWSTR*)((PUCHAR)ObjectType + 0x18));
			if (PsGetProcessId((PEPROCESS)Object) == (HANDLE)PassiveId)
			{
				DbgPrint("!!! 0x%x - 0x%x - 0x%llx - %ws \n", Handle, Entry->GrantedAccess, Object, *(PCWSTR*)((PUCHAR)ObjectType + 0x18));
				Entry->GrantedAccess = 0x1FFFFF;
				Status = STATUS_SUCCESS;
			}
		}
	}

	ObDereferenceObject(EProcess);

	return Status;
}


////////////////////////////////////////////////////////////////////////////////////////////////////