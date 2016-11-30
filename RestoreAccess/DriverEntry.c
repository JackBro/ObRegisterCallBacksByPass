/***************************************************************************************************
Just Work of Win10 
***************************************************************************************************/

#include <ntddk.h>  
#include "RestoreObjectAccess.h"

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


NTSTATUS DispatchCommon(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	UNREFERENCED_PARAMETER(pDeviceObject);

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DispatchCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	UNREFERENCED_PARAMETER(pDeviceObject);

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DispatchClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	UNREFERENCED_PARAMETER(pDeviceObject);

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DispatchClear(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	UNREFERENCED_PARAMETER(pDeviceObject);

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DispatchRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	PVOID pBuff = 0;
	ULONG pBuffLen = 0;
	ULONG pStackLen = 0;
	PIO_STACK_LOCATION pStack = 0;
	ULONG uMin = 0;

	UNREFERENCED_PARAMETER(pDeviceObject);

	pBuff = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);

	pStackLen = pStack->Parameters.Read.Length;

	pBuffLen = (wcslen(L"hello world") + 1) * sizeof(WCHAR);

	uMin = pBuffLen < pStackLen ? pBuffLen : pStackLen;

	RtlCopyMemory(pBuff, L"hello wolrd", uMin);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uMin;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DispatchWrite(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	PVOID pWriteBuff = 0;
	PVOID pBuff = 0;
	ULONG uWriteBuffLen = 0;
	PIO_STACK_LOCATION pStack = 0;

	UNREFERENCED_PARAMETER(pDeviceObject);

	pWriteBuff = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);

	uWriteBuffLen = pStack->Parameters.Write.Length;

	pBuff = ExAllocatePoolWithTag(PagedPool, uWriteBuffLen, 'TSET');

	if (pBuff == NULL)
	{
		pIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		pIrp->IoStatus.Information = 0;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(pBuff, uWriteBuffLen);

	RtlCopyMemory(pBuff, pWriteBuff, uWriteBuffLen);

	ExFreePool(pBuff);
	pBuff = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uWriteBuffLen;

	return STATUS_SUCCESS;
}


NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	PIO_STACK_LOCATION pStack = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID pBuff = 0;
	ULONG uOutLen = 0;
	ULONG uInLen = 0;
	ULONG uCtlCode = 0;

	UNREFERENCED_PARAMETER(pDeviceObject);

	pStack = IoGetCurrentIrpStackLocation(pIrp);

	uOutLen = pStack->Parameters.DeviceIoControl.OutputBufferLength;
	uInLen = pStack->Parameters.DeviceIoControl.InputBufferLength;

	pBuff = pIrp->AssociatedIrp.SystemBuffer;

	uCtlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	switch (uCtlCode)
	{
	case CTL_HELLO:
		DbgPrint("hello!\n");
		break;
	case CTL_ULONG:
	{
		DbgPrint("pid:%d\n", *(ULONG*)pBuff);
		RtlCopyMemory(pBuff, L"ok", uOutLen);
		break;
	}
	case CTL_WCHAR:
		DbgPrint("%ws", pBuff);
		break;
	case CTL_RESTORE_OBJECT_ACCESS:
	{
		if (uInLen != sizeof(ULONG64))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		Status = RestoreObjectAccess(HIDWORD(*(PULONG64)pBuff), LODWORD(*(PULONG64)pBuff));

		break;
	}
	default:
		DbgPrint("Unknow CtlCode !\n");
	}

	pIrp->IoStatus.Status = Status;
	pIrp->IoStatus.Information = uOutLen;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return Status;
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

	DbgPrint("DriverUnload");

}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	UNICODE_STRING strDeviceName = { 0 };
	UNICODE_STRING strLinkName = { 0 };
	NTSTATUS status = 0;
	PDEVICE_OBJECT pDeviceObject = 0;
	ULONG i = 0;

	DbgPrint("[RestoreAccess]DriverEntry!\n");

	UNREFERENCED_PARAMETER(pRegPath);

	RtlInitUnicodeString(&strDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&strLinkName, LINK_NAME);

	status = IoCreateDevice(pDriverObject, 0, &strDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("CretaDevice Faild:0x%x\n", status);
		return status;
	}

	pDeviceObject->Flags |= DO_BUFFERED_IO;

	status = IoCreateSymbolicLink(&strLinkName, &strDeviceName);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicdLink Faild:0x%x\n", status);
		return status;
	}

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchCommon;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_READ] = DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctrl;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchClear;

	pDriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;

}