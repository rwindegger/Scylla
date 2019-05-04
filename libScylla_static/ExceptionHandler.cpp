#include "ExceptionHandler.h"
#include <windows.h>
#include <cstdlib>
#include <cstdio>
#include <psapi.h>
#include "Architecture.h"
#include <tchar.h>

// Default vectored exception handlers
static LPTOP_LEVEL_EXCEPTION_FILTER oldFilter;

#if SCYLLA_USE_MINIDUMP_FOR_CRASH
#include <dbghelp.h>	   // Minidumps creation helpers
LONG WINAPI ScyllaHandleUnknownException(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	HANDLE hFile = CreateFile(_T("ScyllaMiniDump.dmp"), GENERIC_READ | GENERIC_WRITE,
		0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
	{
		// Create the minidump 
		MINIDUMP_EXCEPTION_INFORMATION mdei;

		mdei.ThreadId = GetCurrentThreadId();
		mdei.ExceptionPointers = ExceptionInfo;
		mdei.ClientPointers = FALSE;

		MINIDUMP_CALLBACK_INFORMATION mci;

		mci.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE) NULL;
		mci.CallbackParam = 0;

		MINIDUMP_TYPE mdt = (MINIDUMP_TYPE)(MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory);

		BOOL rv = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
			hFile, mdt, (ExceptionInfo != 0) ? &mdei : 0, 0, &mci);	

		CloseHandle(hFile);

	}


	MessageBox(0, _T("Something went wrong : could you send the ScyllaMiniDump.dmp file to http://www.github.com/NtQuery/Scylla ?") , _T("Scylla crash pad"), MB_ICONERROR);
	return EXCEPTION_CONTINUE_SEARCH;
}
#else
LONG WINAPI ScyllaHandleUnknownException(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	TCHAR registerInfo[220];
	TCHAR filepath[MAX_PATH] = {0};
	TCHAR file[MAX_PATH] = {0};
	TCHAR message[MAX_PATH + 200 + _countof(registerInfo)];
	TCHAR osInfo[100];
    const auto address = reinterpret_cast<DWORD_PTR>(ExceptionInfo->ExceptionRecord->ExceptionAddress);

	_tcscpy_s(filepath, TEXT("unknown"));
	_tcscpy_s(file, TEXT("unknown"));

	if (GetMappedFileName(GetCurrentProcess(), reinterpret_cast<LPVOID>(address), filepath, _countof(filepath)) > 0)
	{
		TCHAR *temp = _tcsrchr(filepath, TEXT('\\'));
		if (temp)
		{
			temp++;
			_tcscpy_s(file, temp);
		}
	}

	_stprintf_s(osInfo, _countof(osInfo), TEXT("Exception! Please report it! OS: %X"), GetVersion());

    const auto moduleBase = reinterpret_cast<DWORD_PTR>(GetModuleHandle(file));
	
	_stprintf_s(message, _countof(message), TEXT("ExceptionCode %08X\r\nExceptionFlags %08X\r\nNumberParameters %08X\r\nExceptionAddress VA ") PRINTF_DWORD_PTR_FULL TEXT(" - Base ") PRINTF_DWORD_PTR_FULL TEXT("\r\nExceptionAddress module %s\r\n\r\n"), 
	ExceptionInfo->ExceptionRecord->ExceptionCode,
	ExceptionInfo->ExceptionRecord->ExceptionFlags, 
	ExceptionInfo->ExceptionRecord->NumberParameters, 
	address,
	moduleBase,
	file);

	

#ifdef _WIN64
	_stprintf_s(registerInfo, _countof(registerInfo), TEXT("rax=0x%llx, rbx = 0x%llx, rdx = 0x%llx, rcx = 0x%llx, rsi = 0x%llx, rdi = 0x%llx, rbp = 0x%llx, rsp = 0x%llx, rip = 0x%llx"),
		ExceptionInfo->ContextRecord->Rax,
		ExceptionInfo->ContextRecord->Rbx,
		ExceptionInfo->ContextRecord->Rdx,
		ExceptionInfo->ContextRecord->Rcx,
		ExceptionInfo->ContextRecord->Rsi,
		ExceptionInfo->ContextRecord->Rdi,
		ExceptionInfo->ContextRecord->Rbp,
		ExceptionInfo->ContextRecord->Rsp,
		ExceptionInfo->ContextRecord->Rip
		);
#else
	_stprintf_s(registerInfo, _countof(registerInfo), TEXT("eax=0x%lx, ebx=0x%lx, edx=0x%lx, ecx=0x%lx, esi=0x%lx, edi=0x%lx, ebp=0x%lx, esp=0x%lx, eip=0x%lx"),
		ExceptionInfo->ContextRecord->Eax,
		ExceptionInfo->ContextRecord->Ebx,
		ExceptionInfo->ContextRecord->Edx,
		ExceptionInfo->ContextRecord->Ecx,
		ExceptionInfo->ContextRecord->Esi,
		ExceptionInfo->ContextRecord->Edi,
		ExceptionInfo->ContextRecord->Ebp,
		ExceptionInfo->ContextRecord->Esp,
		ExceptionInfo->ContextRecord->Eip
		);
#endif

	_tcscat_s(message, _countof(message), registerInfo);

	MessageBox(nullptr, message, osInfo, MB_ICONERROR);

	return EXCEPTION_CONTINUE_SEARCH;
}
#endif


void AddScyllaUnhandledExceptionHandler()
{
	oldFilter = SetUnhandledExceptionFilter(ScyllaHandleUnknownException);
}
void RemoveScyllaUnhandledExceptionHandler()
{
	SetUnhandledExceptionFilter(oldFilter);
}