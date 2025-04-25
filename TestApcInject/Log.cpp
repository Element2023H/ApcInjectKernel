#include "Log.hpp"
#include <ntstrsafe.h>
#include <stdarg.h>

extern HANDLE g_hFile;

NTSTATUS
InitializeLogFile(IN CONST PWCHAR FilePath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (!FilePath)
	{
		return status;
	}

	__try
	{
		UNICODE_STRING ustrFilePath{};
		RtlInitUnicodeString(&ustrFilePath, FilePath);

		OBJECT_ATTRIBUTES oa{};
		InitializeObjectAttributes(&oa, &ustrFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		IO_STATUS_BLOCK ioStatusBlock{};

		status = ZwCreateFile(&g_hFile,
			GENERIC_WRITE | SYNCHRONIZE,
			&oa,
			&ioStatusBlock,
			nullptr,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OVERWRITE_IF,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			nullptr, 0);

		if (NT_SUCCESS(status))
		{
		}

	}
	__finally
	{
		
	}

	return status;
}

NTSTATUS
WriteLogToFile(IN CONST PCHAR LogInfo)
{
	NTSTATUS status = STATUS_SUCCESS;

	
	if (!g_hFile)
	{
		return STATUS_UNSUCCESSFUL;
	}

	IO_STATUS_BLOCK ioStatusBlock{};
	//auto dataSize = static_cast<ULONG>(strlen(LogInfo));
	status = ZwWriteFile(
		g_hFile,
		nullptr,
		nullptr,
		nullptr,
		&ioStatusBlock,
		LogInfo,
		static_cast<ULONG>(strlen(LogInfo)),
		nullptr, nullptr);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("status = %08X", status);
		return status;
	}

	
	status = ZwFlushBuffersFile(g_hFile, &ioStatusBlock);
	

	return status;
}

//
// At APC irql folowing formats are denied:
// %C, %S, %lc, %ls, %wc, %ws, and %wZ
//
bool
CheckFormatSupportAPC(const char* sFormat)
{
	// Find denied symbols
	for (const char* pCur = sFormat; *pCur != 0; ++pCur)
	{
		if (*pCur != '%') continue;
		switch (pCur[1])
		{
		case '%':
			++pCur;
			break;
		case 'C':
		case 'S':
			return false;
		case 'l':
		case 'w':
			if (pCur[2] == 'c' || pCur[2] == 's' || pCur[2] == 'Z')
				return false;
			break;
		}
	}

	return true;
}

static
void
vLogInfo(const char* sFormat, va_list va)
{

	// Logging work at IRQL <= APC_LEVEL
	if (KeGetCurrentIrql() >= APC_LEVEL)
	{
		return;
	}
	// Special process for APC_LEVEL
	if (KeGetCurrentIrql() == APC_LEVEL && !CheckFormatSupportAPC(sFormat))
	{
		return;
	}

	if (!g_hFile)
	{
		return;
	}


	// output to DbgView
	vDbgPrintExWithPrefix("[output]", DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, sFormat, va);



	// Format to buffer. If result data too large then truncate.
	char pBuffer[512] = { 0 };
	size_t nDataSize = 0;

	NTSTATUS status = RtlStringCbVPrintfA(pBuffer, sizeof(pBuffer), sFormat, va);
	{
		if (NT_ERROR(status) && status != STATUS_BUFFER_OVERFLOW)
		{
			return;
		}
		status = RtlStringCbLengthA(pBuffer, sizeof(pBuffer), &nDataSize);
		if (NT_ERROR(status))
		{
			return;
		}
	}

	__try
	{
		
		status = WriteLogToFile(pBuffer);


	}
	__finally
	{
		
	}

}


void
LogInfo(const char* sFormat, ...)
{
	va_list va;
	va_start(va, sFormat);
	vLogInfo(sFormat, va);
	va_end(va);
}