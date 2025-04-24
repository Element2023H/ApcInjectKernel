#include "ApcInject.h"

constexpr ULONG APCINJECT_MEM_TAG = 'mpAK';

EXTERN_C NTSTATUS NTSYSAPI ZwGetNextThread(
	HANDLE ProcessHandle,
	HANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	ULONG HandleAttributes,
	ULONG Flags,
	PHANDLE NewThreadHandle
	);

WCHAR*
KWstrnstr(
	const WCHAR* src,
	const WCHAR* find)
{
	WCHAR* cp = (WCHAR*)src;
	WCHAR* s1 = NULL, * s2 = NULL;

	if (NULL == src ||
		NULL == find)
	{
		return NULL;
	}

	while (*cp)
	{
		s1 = cp;
		s2 = (WCHAR*)find;

		while (*s2 && *s1 && !(towlower(*s1) - towlower(*s2)))
		{
			s1++, s2++;
		}

		if (!(*s2))
		{
			return cp;
		}

		cp++;
	}
	return NULL;
}

PVOID 
KGetProcAddress(
	IN CONST HANDLE ModuleHandle,
	CONST PCHAR FuncName)
{
	PIMAGE_DOS_HEADER       DosHeader = NULL;
	PIMAGE_NT_HEADERS       NtHeader = NULL;
	PIMAGE_DATA_DIRECTORY   ExportsDir = NULL;
	PIMAGE_EXPORT_DIRECTORY Exports = NULL;
#ifdef _WIN64
	PIMAGE_NT_HEADERS32		pNtHeaders32;
#endif
	PULONG Functions = NULL;
	PSHORT Ordinals = NULL;
	PULONG Names = NULL;
	ULONG64 ProcAddr = 0;
	ULONG NumOfFunc = 0;

	ULONG i = 0, NumOfNames = 0, iOrd = 0, nSize = 0, ulImageSize = 0;

	if (!ModuleHandle || !FuncName)
	{
		return NULL;
	}

	DosHeader	= (PIMAGE_DOS_HEADER)ModuleHandle;

	NtHeader	= (PIMAGE_NT_HEADERS)((PUCHAR)ModuleHandle + DosHeader->e_lfanew);

	if (!NtHeader)
	{
		return NULL;
	}
#ifdef _WIN64
	if (NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		ExportsDir		= NtHeader->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
		ulImageSize		= NtHeader->OptionalHeader.SizeOfImage;
	}
	else
	{
		pNtHeaders32	= (PIMAGE_NT_HEADERS32)NtHeader;
		ExportsDir		= pNtHeaders32->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
		ulImageSize		= NtHeader->OptionalHeader.SizeOfImage;
	}
#else
	ExportsDir = NtHeader->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	ulImageSize = NtHeader->OptionalHeader.SizeOfImage;
#endif 
	if (!ExportsDir)
	{
		return NULL;
	}

	Exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleHandle + ExportsDir->VirtualAddress);

	if (!Exports)
	{
		return NULL;
	}

	Functions	= (PULONG)((PUCHAR)ModuleHandle + Exports->AddressOfFunctions);
	Ordinals	= (PSHORT)((PUCHAR)ModuleHandle + Exports->AddressOfNameOrdinals);
	Names		= (PULONG)((PUCHAR)ModuleHandle + Exports->AddressOfNames);

	NumOfNames = Exports->NumberOfNames;
	ProcAddr = ExportsDir->VirtualAddress;
	NumOfFunc = Exports->NumberOfFunctions;

	nSize = ExportsDir->Size;
	__try
	{
		for (i = 0; i < NumOfNames; i++)
		{
			iOrd = Ordinals[i];
			if (iOrd >= NumOfFunc)
			{
				continue;
			}

			if (Functions[iOrd] > 0 && Functions[iOrd] < ulImageSize)
			{
				if (_stricmp((char*)ModuleHandle + Names[i], FuncName) == 0)
				{
					return (PVOID)((char*)ModuleHandle + Functions[iOrd]);
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	return NULL;
}


typedef struct _INJECT_BUFFER
{
	UCHAR code[0x200];
	union
	{
		UNICODE_STRING		path;
		UNICODE_STRING32	path32;;
	};

	wchar_t buffer[488];
	PVOID module;
	ULONG complete;
	NTSTATUS status;
} INJECT_BUFFER, * PINJECT_BUFFER;




static
PINJECT_BUFFER
BuildWow64Code(
	IN HANDLE			ProcessHandle,
	IN PVOID			LdrLoadDll,
	IN PUNICODE_STRING	DllPath)
{
	NTSTATUS		status = STATUS_SUCCESS;
	PINJECT_BUFFER	pBuffer = NULL;
	SIZE_T			size = PAGE_SIZE;

	// Code
	UCHAR code[] =
	{
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
		0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +6
		0x6A, 0,                                // push Flags  
		0x6A, 0,                                // push PathToFile
		0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +15
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [edx], CALL_COMPLETE     
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +31
		0x89, 0x02,                             // mov [edx], eax
		0xC2, 0x04, 0x00                        // ret 4
	};

	// 目标进程申请内存空间保存APC_INJECT的shellcode
	// 便于之后在apc执行shellcode
	status = ZwAllocateVirtualMemory(ProcessHandle,
		(PVOID*)&pBuffer,
		0,
		&size,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(status))
	{
		// Copy path
		PUNICODE_STRING32 pUserPath = &pBuffer->path32;
		pUserPath->Length = DllPath->Length;
		pUserPath->MaximumLength = DllPath->MaximumLength;
		pUserPath->Buffer = (ULONG)(ULONG_PTR)pBuffer->buffer;

		// Copy path
		memcpy((PVOID)pUserPath->Buffer, DllPath->Buffer, DllPath->Length);

		// Copy code
		memcpy(pBuffer, code, sizeof(code));

		// Fill stubs
		*(ULONG*)((PUCHAR)pBuffer + 1) = (ULONG)(ULONG_PTR)&pBuffer->module;
		*(ULONG*)((PUCHAR)pBuffer + 6) = (ULONG)(ULONG_PTR)pUserPath;
		*(ULONG*)((PUCHAR)pBuffer + 15) = (ULONG)((ULONG_PTR)LdrLoadDll - ((ULONG_PTR)pBuffer + 15) - 5 + 1);
		*(ULONG*)((PUCHAR)pBuffer + 20) = (ULONG)(ULONG_PTR)&pBuffer->complete;
		*(ULONG*)((PUCHAR)pBuffer + 31) = (ULONG)(ULONG_PTR)&pBuffer->status;

		return pBuffer;
	}

	UNREFERENCED_PARAMETER(DllPath);
	return NULL;
}


static
PINJECT_BUFFER 
BuildNativeCode(
	IN HANDLE			ProcessHandle,
	IN PVOID			LdrLoadDll, 
	IN PUNICODE_STRING	pPath)
{
	NTSTATUS status			= STATUS_SUCCESS;
	PINJECT_BUFFER pBuffer	= NULL;
	SIZE_T size				= PAGE_SIZE;

	// Code
	UCHAR code[] =
	{
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
		0x48, 0x31, 0xC9,                       // xor rcx, rcx
		0x48, 0x31, 0xD2,                       // xor rdx, rdx
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +28
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
		0xFF, 0xD0,                             // call rax
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +44
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE 
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +60
		0x89, 0x02,                             // mov [rdx], eax
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
		0xC3                                    // ret
	};

	status = ZwAllocateVirtualMemory(ProcessHandle,
									 (PVOID*)&pBuffer, 
									 0, 
									 &size, 
									 MEM_COMMIT, 
									 PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(status))
	{
		// Copy path
		PUNICODE_STRING pUserPath	= &pBuffer->path;
		pUserPath->Length			= 0;
		pUserPath->MaximumLength	= sizeof(pBuffer->buffer);
		pUserPath->Buffer			= pBuffer->buffer;

		RtlUnicodeStringCopy(pUserPath, pPath);

		// Copy code
		memcpy(pBuffer, code, sizeof(code));

		// Fill stubs
		*(ULONGLONG*)((PUCHAR)pBuffer + 12) = (ULONGLONG)pUserPath;
		*(ULONGLONG*)((PUCHAR)pBuffer + 22) = (ULONGLONG)&pBuffer->module;
		*(ULONGLONG*)((PUCHAR)pBuffer + 32) = (ULONGLONG)LdrLoadDll;
		*(ULONGLONG*)((PUCHAR)pBuffer + 44) = (ULONGLONG)&pBuffer->complete;
		*(ULONGLONG*)((PUCHAR)pBuffer + 60) = (ULONGLONG)&pBuffer->status;

		return pBuffer;
	}

	UNREFERENCED_PARAMETER(pPath);
	return NULL;
}

static
NTSTATUS
KGetProcessFirstEThread(
	HANDLE		ProcessId, 
	PETHREAD*	Thread)
{
	NTSTATUS                    Status = STATUS_SUCCESS;
	ULONG                       ulRetLength = 0;
	PSYSTEM_PROCESS_INFORMATION pTmp = NULL;
	PSYSTEM_THREAD_INFORMATION  pSysThread = NULL;
	PSYSTEM_PROCESS_INFORMATION pSysProcessesInfo = NULL;

	Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &ulRetLength);
	if (Status == STATUS_INFO_LENGTH_MISMATCH)
	{

		pSysProcessesInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(ExAllocatePoolWithTag(NonPagedPool, ulRetLength, APCINJECT_MEM_TAG));
		if (!pSysProcessesInfo)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		Status = ZwQuerySystemInformation(SystemProcessInformation, pSysProcessesInfo, ulRetLength, &ulRetLength);
		if (!NT_SUCCESS(Status))
		{
			ExFreePoolWithTag(pSysProcessesInfo, APCINJECT_MEM_TAG);
			return Status;
		}
	}
	else if (Status != STATUS_SUCCESS)
	{
		return Status;
	}

	pTmp = pSysProcessesInfo;
	while (TRUE)
	{
		if (pTmp->UniqueProcessId == ProcessId)
		{
			pSysThread = (PSYSTEM_THREAD_INFORMATION)(pTmp + 1);
			break;
		}

		if (!pTmp->NextEntryOffset)
		{
			break;
		}

		pTmp = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)pTmp + pTmp->NextEntryOffset);
	}

	if (pSysThread && Thread)
	{
		Status = PsLookupThreadByThreadId(pSysThread->ClientId.UniqueThread, Thread);
	}
	else
	{
		Status = STATUS_UNSUCCESSFUL;
	}

	if (pSysProcessesInfo)
	{
		ExFreePoolWithTag(pSysProcessesInfo, APCINJECT_MEM_TAG);
	}
	return Status;
}

// a improved version of KGetProcessFirstEThread
NTSTATUS KGetProcessMainThread(HANDLE ProcessId, PETHREAD* ppThread)
{
	NTSTATUS status{ STATUS_SUCCESS };
	PEPROCESS Process{ nullptr };
	HANDLE hProcess{ nullptr };
	HANDLE hMainThread{ nullptr };

	if (ppThread == nullptr)
	{
		return STATUS_INVALID_ADDRESS;
	}

	status = PsLookupProcessByProcessId(ProcessId, &Process);

	if (NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &hProcess);

		if (NT_SUCCESS(status))
		{
			status = ZwGetNextThread(hProcess, nullptr, GENERIC_ALL, OBJ_KERNEL_HANDLE, 0, &hMainThread);
		}
	}

	if (NT_SUCCESS(status))
	{
		PETHREAD MainThread{ nullptr };

		status = ObReferenceObjectByHandle(hMainThread, THREAD_QUERY_LIMITED_INFORMATION, *PsThreadType, KernelMode, (PVOID*)&MainThread, NULL);

		if (NT_SUCCESS(status))
		{
			*ppThread = MainThread;
		}
	}

	if (hProcess != nullptr)
	{
		ZwClose(hProcess);
	}

	if (Process != nullptr)
	{
		ObDereferenceObject(Process);
	}

	if (hMainThread != nullptr)
	{
		ZwClose(hMainThread);
	}

	return status;
}

static
VOID
ApcInjectKernelRoutine(
	__in struct _KAPC* Apc,
	__deref_inout_opt PKNORMAL_ROUTINE* NormalRoutine,
	__deref_inout_opt PVOID* NormalContext,
	__deref_inout_opt PVOID* SystemArgument1,
	__deref_inout_opt PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);


	// Skip execution
	if (PsIsThreadTerminating(PsGetCurrentThread()))
	{
		*NormalRoutine = NULL;
	}

	// Fix Wow64 APC
	if (PsGetCurrentProcessWow64Process())
	{
		PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);
	}


	if (Apc)
	{
		ExFreePoolWithTag(Apc, APCINJECT_MEM_TAG);
	}
}

VOID
ApcInjectNormalRoutine(
	__in_opt PVOID NormalContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PKAPC   Apc = NULL;
	PUCHAR	ShellCodeApc = reinterpret_cast<PUCHAR>(NormalContext);

	Apc = reinterpret_cast<PKAPC>(ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), APCINJECT_MEM_TAG));
	if (Apc)
	{
		KeInitializeApc(Apc,
			(PKTHREAD)PsGetCurrentThread(),
			OriginalApcEnvironment,
			ApcInjectKernelRoutine,
			NULL,
			(PKNORMAL_ROUTINE)ShellCodeApc,
			UserMode,
			NULL);

		if (!KeInsertQueueApc(Apc, NULL, NULL, IO_NO_INCREMENT))
		{
			ExFreePoolWithTag(Apc, APCINJECT_MEM_TAG);
		}
	}
}

static
NTSTATUS
ApcInjectWow64(
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo,
	PUNICODE_STRING InjectDllPath)
{
	NTSTATUS		status{ STATUS_SUCCESS };

	PINJECT_BUFFER	pUserBuffer{ nullptr };

	PEPROCESS		pEprocess{ nullptr };
	HANDLE			hProcess{ nullptr };
	PVOID			pLdrLoadDll{ nullptr };

	PETHREAD		pEthread{ nullptr };
	PKAPC			pApc{ nullptr };

	status = PsLookupProcessByProcessId(ProcessId, &pEprocess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	do
	{
		status = ObOpenObjectByPointer(pEprocess,
			OBJ_KERNEL_HANDLE,
			NULL,
			PROCESS_ALL_ACCESS,
			NULL,
			KernelMode,
			&hProcess);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		pLdrLoadDll = KGetProcAddress(ImageInfo->ImageBase, "LdrLoadDll");
		if (!pLdrLoadDll)
		{
			DbgPrint("KGetProcAddress failed line:%d in %s\r\n", __LINE__, __FUNCTION__);
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		pUserBuffer = BuildWow64Code(hProcess, pLdrLoadDll, InjectDllPath);
		if (!pUserBuffer)
		{
			DbgPrint("BuildNativeCode failed line:%d in %s\r\n", __LINE__, __FUNCTION__);
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		// Kernel Exports Added for Windows 10 Version 1709
		// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/history/names1709.htm?ta=11&tx=42;25
		if (*NtBuildNumber >= 16299)
		{
			status = KGetProcessMainThread(ProcessId, &pEthread);
		}
		else
		{
			status = KGetProcessFirstEThread(ProcessId, &pEthread);
		}

		if (!NT_SUCCESS(status))
		{
			DbgPrint("KGetProcessFirstEThread failed line:%d in %s\r\n", __LINE__, __FUNCTION__);
			break;
		}

		// 申请apc
		pApc = reinterpret_cast<PKAPC>(ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), APCINJECT_MEM_TAG));
		if (!pApc)
		{
			break;
		}

		KeInitializeApc(pApc,
			(PKTHREAD)pEthread,
			OriginalApcEnvironment,
			ApcInjectKernelRoutine,
			NULL,
			(PKNORMAL_ROUTINE)(ULONG_PTR)pUserBuffer->code,
			UserMode,
			NULL);

		// 插入apc queue
		if (!KeInsertQueueApc(pApc, NULL, NULL, IO_NO_INCREMENT))
		{
			ExFreePoolWithTag(pApc, APCINJECT_MEM_TAG);
		}

	} while (FALSE);

	if (pEthread)
	{
		ObDereferenceObject(pEthread);
	}

	if (hProcess)
	{
		ZwClose(hProcess);
	}

	if (pEprocess)
	{
		ObDereferenceObject(pEprocess);
	}


	return status;
}

static
NTSTATUS
ApcInjectNative(
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo,
	PUNICODE_STRING InjectDllPath)
{
	NTSTATUS		status{ STATUS_SUCCESS };

	PINJECT_BUFFER	pUserBuffer{ nullptr };

	PEPROCESS		pEprocess{ nullptr };
	HANDLE			hProcess{ nullptr };
	PVOID			pLdrLoadDll{ nullptr };

	PETHREAD		pEthread{ nullptr };
	PKAPC			pApc{ nullptr };

	status = PsLookupProcessByProcessId(ProcessId, &pEprocess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	do 
	{
		status = ObOpenObjectByPointer(pEprocess,
			OBJ_KERNEL_HANDLE,
			NULL,
			PROCESS_ALL_ACCESS,
			NULL,
			KernelMode,
			&hProcess);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		pLdrLoadDll = KGetProcAddress(ImageInfo->ImageBase, "LdrLoadDll");
		if (!pLdrLoadDll)
		{
			DbgPrint("KGetProcAddress failed line:%d in %s\r\n", __LINE__, __FUNCTION__);
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		pUserBuffer = BuildNativeCode(hProcess, pLdrLoadDll, InjectDllPath);
		if (!pUserBuffer)
		{
			DbgPrint("BuildNativeCode failed line:%d in %s\r\n", __LINE__, __FUNCTION__);
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		// Kernel Exports Added for Windows 10 Version 1709
		// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/history/names1709.htm?ta=11&tx=42;25
		if (*NtBuildNumber >= 16299)
		{
			status = KGetProcessMainThread(ProcessId, &pEthread);
		}
		else
		{
			status = KGetProcessFirstEThread(ProcessId, &pEthread);
		}

		if (!NT_SUCCESS(status))
		{
			DbgPrint("KGetProcessFirstEThread failed line:%d in %s\r\n", __LINE__, __FUNCTION__);
			break;
		}

		// 申请apc
		pApc = reinterpret_cast<PKAPC>(ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), APCINJECT_MEM_TAG));
		if (!pApc)
		{
			break;
		}

		KeInitializeApc(pApc,
			(PKTHREAD)pEthread,
			OriginalApcEnvironment,
			ApcInjectKernelRoutine,
			NULL,
			ApcInjectNormalRoutine,
			KernelMode,
			(UCHAR*)pUserBuffer->code);

		// 插入apc queue
		if (!KeInsertQueueApc(pApc, NULL, NULL, IO_NO_INCREMENT))
		{
			ExFreePoolWithTag(pApc, APCINJECT_MEM_TAG);
		}

	} while (FALSE);

	if (pEthread)
	{
		ObDereferenceObject(pEthread);
	}

	if (hProcess)
	{
		ZwClose(hProcess);
	}

	if (pEprocess)
	{
		ObDereferenceObject(pEprocess);
	}


	return status;
}


VOID 
NTAPI
ApcInjectNativeProcess(
	PUNICODE_STRING FullImageName, 
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo, 
	PUNICODE_STRING InjectDllPath)
{
	if (KWstrnstr(FullImageName->Buffer, L"\\System32\\ntdll.dll"))
	{
		NTSTATUS status = ApcInjectNative(ProcessId, ImageInfo, InjectDllPath);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("ApcInjectNative failed in line:%d %s\r\n", __LINE__, __FUNCTION__);
		}
	}
}


VOID
NTAPI
ApcInjectWow64Process(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo,
	PUNICODE_STRING InjectDllPath)
{
	if (KWstrnstr(FullImageName->Buffer, L"\\SysWOW64\\ntdll.dll"))
	{
		NTSTATUS status = ApcInjectWow64(ProcessId, ImageInfo, InjectDllPath);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("ApcInjectNative failed in line:%d %s\r\n", __LINE__, __FUNCTION__);
		}
	}
}