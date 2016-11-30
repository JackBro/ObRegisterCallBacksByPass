#include <ntddk.h>  
#include "RestoreAccess.h"

#define DEVICE_NAME L"\\device\\RestoreAccess"  
#define LINK_NAME L"\\dosdevices\\RestoreAccess" //\\??\\xxxx  

#define IOCTRL_BASE 0x800  

#define IOCTL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CTL_HELLO IOCTL_CODE(0)  
#define CTL_ULONG IOCTL_CODE(1)  
#define CTL_WCHAR IOCTL_CODE(2)  
#define CTL_RESTORE_OBJECT_ACCESS IOCTL_CODE(3)


#define LODWORD(l)	((ULONG32)(((ULONG_PTR)(l)) & 0xffffffff))
#define HIDWORD(l)	((ULONG32)((((ULONG_PTR)(l)) >> 32) & 0xffffffff))


NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	PVOID pReadBuffer = NULL;
	ULONG uReadLength = 0;
	PIO_STACK_LOCATION pStack = NULL;
	ULONG uMin = 0;
	ULONG uHelloStr = 0;

	uHelloStr = (wcslen(L"hello world") + 1) * sizeof(WCHAR);

	pReadBuffer = pIrp->AssociatedIrp.SystemBuffer;
	pStack = IoGetCurrentIrpStackLocation(pIrp);

	uReadLength = pStack->Parameters.Read.Length;
	uMin = uReadLength>uHelloStr ? uHelloStr : uReadLength;

	RtlCopyMemory(pReadBuffer, L"hello world", uMin);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uMin;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}

NTSTATUS DispatchWrite(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	PVOID pWriteBuff = NULL;
	ULONG uWriteLength = 0;
	PIO_STACK_LOCATION pStack = NULL;

	PVOID pBuffer = NULL;

	pWriteBuff = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uWriteLength = pStack->Parameters.Write.Length;

	pBuffer = ExAllocatePoolWithTag(PagedPool, uWriteLength, 'TSET');
	if (pBuffer == NULL)
	{
		pIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		pIrp->IoStatus.Information = 0;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	memset(pBuffer, 0, uWriteLength);

	RtlCopyMemory(pBuffer, pWriteBuff, uWriteLength);

	ExFreePool(pBuffer);
	pBuffer = NULL;


	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uWriteLength;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}

NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	ULONG uIoctrlCode = 0;
	PVOID pInputBuff = NULL;
	PVOID pOutputBuff = NULL;

	ULONG uInputLength = 0;
	ULONG uOutputLength = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pStack = NULL;

	pInputBuff = pOutputBuff = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uInputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;


	uIoctrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	switch (uIoctrlCode)
	{
	case CTL_HELLO:
		DbgPrint("Hello iocontrol\n");
		break;
	case CTL_WCHAR:
		DbgPrint("%ws\n", pInputBuff);
		break;
	case CTL_ULONG:
		DbgPrint("Goodbye iocontrol\n");
		break;
	case CTL_RESTORE_OBJECT_ACCESS:
		{
			if (uInputLength != sizeof(ULONG64))
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			Status = RestoreObjectAccess(HIDWORD(*(PULONG64)pInputBuff), LODWORD(*(PULONG64)pInputBuff));

			break;
		}
	default:
		DbgPrint("Unknown iocontrol\n");

	}

	pIrp->IoStatus.Status = Status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return Status;

}

NTSTATUS DispatchClean(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING strLinkName = { 0 };

	RtlInitUnicodeString(&strLinkName, LINK_NAME);

	IoDeleteSymbolicLink(&strLinkName);

	if (pDriverObject->DeviceObject)
	{
		IoDeleteDevice(pDriverObject->DeviceObject);
	}

	DbgPrint("Driver unloaded\n");

}

extern "C"	NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegPath)
{
	UNICODE_STRING uDeviceName = { 0 };
	UNICODE_STRING uLinkName = { 0 };
	NTSTATUS ntStatus = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	ULONG i = 0;

	DbgPrint("Driver load begin\n");

	RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uLinkName, LINK_NAME);

	ntStatus = IoCreateDevice(pDriverObject,
		0, &uDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice failed:%x", ntStatus);
		return ntStatus;
	}

	pDeviceObject->Flags |= DO_BUFFERED_IO;

	ntStatus = IoCreateSymbolicLink(&uLinkName, &uDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicLink failed:%x\n", ntStatus);
		return ntStatus;
	}

	for (i = 0; i<IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchCommon;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctrl;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchClean;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;

	pDriverObject->DriverUnload = DriverUnload;

	DbgPrint("Driver load ok!\n");

	//RestoreObjectAccess(1464, 1464);

	return STATUS_SUCCESS;
}