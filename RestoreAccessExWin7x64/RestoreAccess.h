#pragma once

#define HANDLE_VALUE_INC 4

#define TABLE_PAGE_SIZE	PAGE_SIZE
#define LOWLEVEL_COUNT (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
#define MIDLEVEL_COUNT (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY))

#define HANDLE_TABLE_OFFSET_WIN7	0x200

#define LEVEL_CODE_MASK 3

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


extern "C"	NTSTATUS RestoreObjectAccess(ULONG32 ActiveId, ULONG32 PassiveId);

typedef struct _EXHANDLE
{
	union
	{
		struct
		{
			ULONG32 TagBits : 2;
			ULONG32 Index : 30;
		};
		HANDLE GenericHandleOverlay;
		ULONG_PTR Value;
	};
} EXHANDLE, *PEXHANDLE;

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
