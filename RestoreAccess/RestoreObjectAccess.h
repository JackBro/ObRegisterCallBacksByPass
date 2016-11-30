#pragma once


////////////////////////////////////////////////////////////////////////////////////////////////////


#ifndef RESTORE_OBJECT_ACCESS_H
#define RESTORE_OBJECT_ACCESS_H


////////////////////////////////////////////////////////////////////////////////////////////////////


#pragma warning(disable:4201)
#pragma warning(disable:4214)


////////////////////////////////////////////////////////////////////////////////////////////////////


#define HANDLE_TABLE_OFFSET_WIN7	0x200
#define HANDLE_TABLE_OFFSET_WIN10	0x418


////////////////////////////////////////////////////////////////////////////////////////////////////


#define HANDLE_VALUE_INC 4

#define TABLE_PAGE_SIZE	PAGE_SIZE
#define LOWLEVEL_COUNT (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
#define MIDLEVEL_COUNT (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY))

#define LEVEL_CODE_MASK 3


////////////////////////////////////////////////////////////////////////////////////////////////////


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


typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		LONG_PTR VolatileLowValue;
		LONG_PTR LowValue;
		PVOID InfoTable;
		LONG_PTR RefCountField;
		struct
		{
			ULONG_PTR Unlocked : 1;
			ULONG_PTR RefCnt : 16;
			ULONG_PTR Attributes : 3;
			ULONG_PTR ObjectPointerBits : 44;
		};
	};
	union
	{
		LONG_PTR HighValue;
		struct _HANDLE_TABLE_ENTRY *NextFreeHandleEntry;
		EXHANDLE LeafHandleValue;
		struct
		{
			ULONG32 GrantedAccessBits : 25;
			ULONG32 NoRightsUpgrade : 1;
			ULONG32 Spare1 : 6;
		};
		ULONG32 Spare2;
	};
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;


typedef struct _HANDLE_TABLE_FREE_LIST
{
	ULONG_PTR FreeListLock;
	PHANDLE_TABLE_ENTRY FirstFreeHandleEntry;
	PHANDLE_TABLE_ENTRY lastFreeHandleEntry;
	LONG32 HandleCount;
	ULONG32 HighWaterMark;
	ULONG32 Reserved[8];
} HANDLE_TABLE_FREE_LIST, *PHANDLE_TABLE_FREE_LIST;


typedef struct _HANDLE_TABLE
{
	ULONG32 NextHandleNeedingPool;
	LONG32 ExtraInfoPages;
	ULONG_PTR TableCode;
	PEPROCESS QuotaProcess;
	LIST_ENTRY HandleTableList;
	ULONG32 UniqueProcessId;
	union
	{
		ULONG32 Flags;
		struct
		{
			BOOLEAN StrictFIFO : 1;
			BOOLEAN EnableHandleExceptions : 1;
			BOOLEAN Rundown : 1;
			BOOLEAN Duplicated : 1;
			BOOLEAN RaiseUMExceptionOnInvalidHandleClose : 1;
		};
	};
	ULONG_PTR HandleContentionEvent;
	ULONG_PTR HandleTableLock;
	union
	{
		HANDLE_TABLE_FREE_LIST FreeLists[1];
		BOOLEAN ActualEntry[32];
	};
	PVOID DebugInfo;
} HANDLE_TABLE, *PHANDLE_TABLE;


////////////////////////////////////////////////////////////////////////////////////////////////////


NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
	__in HANDLE ProcessId,
	__deref_out PEPROCESS *Process
);


NTKERNELAPI POBJECT_TYPE ObGetObjectType(PVOID Object);


////////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS RestoreObjectAccess(ULONG32 ActiveId, ULONG32 PassiveId);


////////////////////////////////////////////////////////////////////////////////////////////////////


#endif


//////////////////////////////////////////// End Of File ///////////////////////////////////////////