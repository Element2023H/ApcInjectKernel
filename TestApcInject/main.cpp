#include "../ApcInject.h"
#include "Log.hpp"

UNICODE_STRING g_InjectDll;
UNICODE_STRING g_InjectDll32;

HANDLE g_hFile{ nullptr };


EXTERN_C
{


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath);


};


VOID 
PloadImageNotifyRoutine(
	_In_  PUNICODE_STRING FullImageName,
	_In_  HANDLE ProcessId,
	_In_  PIMAGE_INFO ImageInfo
)
{
	if (HandleToULong(ProcessId) <= 4)
	{
		return;
	}

	NTSTATUS status{ STATUS_SUCCESS };
	PUNICODE_STRING pProcessImage{ nullptr };
	PEPROCESS pProcess{ nullptr };
	status = PsLookupProcessByProcessId(ProcessId, &pProcess);
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "PsLookupProcessByProcessId failed. ProcessId: %d", HandleToULong(ProcessId));
		return;
	}

	status = SeLocateProcessImageName(pProcess, &pProcessImage);
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "SeLocateProcessImageName failed. ProcessId: %d", HandleToULong(ProcessId));
		ObDereferenceObject(pProcess);
		return;
	}

	// test ... .. .
	if (pProcessImage && pProcessImage->Buffer)
	{
		if (KWstrnstr(pProcessImage->Buffer, L"system32\\notepad.exe") && 
			KWstrnstr(FullImageName->Buffer, L"system32\\ntdll.dll"))
		{
			//DbgBreakPoint();
			ApcInjectNativeProcess(FullImageName, ProcessId, ImageInfo, &g_InjectDll);
		}
		else if (KWstrnstr(pProcessImage->Buffer, L"SysWOW64\\notepad.exe") &&
			KWstrnstr(FullImageName->Buffer, L"SysWOW64\\ntdll.dll"))
		{
			//DbgBreakPoint();
			ApcInjectWow64Process(FullImageName, ProcessId, ImageInfo, &g_InjectDll32);
		}

		ExFreePool(pProcessImage);
		ObDereferenceObject(pProcess);
	}

}

VOID
DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	if (g_hFile)
	{
		ZwClose(g_hFile);
		g_hFile = nullptr;
	}
	PsRemoveLoadImageNotifyRoutine(reinterpret_cast<PLOAD_IMAGE_NOTIFY_ROUTINE>(PloadImageNotifyRoutine));
}

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status{ STATUS_SUCCESS };

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	RtlInitUnicodeString(&g_InjectDll, L"C:\\InjectDir\\InjectDll_x64.dll");
	RtlInitUnicodeString(&g_InjectDll32, L"C:\\InjectDir\\InjectDll_x86.dll");

	
	DriverObject->DriverUnload = DriverUnload;

	status = InitializeLogFile(L"\\??\\C:\\desktop\\Log.txt");
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("status = %08X", status);
		LOGERROR(status, "InitializeLogFile");
	}

	status = PsSetLoadImageNotifyRoutine(reinterpret_cast<PLOAD_IMAGE_NOTIFY_ROUTINE>(PloadImageNotifyRoutine));
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("PsSetLoadImageNotifyRoutine failed status = %08X", status);
		LOGERROR(status, "PsSetLoadImageNotifyRoutine failed");
	}


	return status;
}