#include "NativeWinApi.h"

def_NtCreateThreadEx NativeWinApi::NtCreateThreadEx = nullptr;
def_NtDuplicateObject NativeWinApi::NtDuplicateObject = nullptr;
def_NtOpenProcess NativeWinApi::NtOpenProcess = nullptr;
def_NtOpenThread NativeWinApi::NtOpenThread = nullptr;
def_NtQueryObject NativeWinApi::NtQueryObject = nullptr;
def_NtQueryInformationFile NativeWinApi::NtQueryInformationFile = nullptr;
def_NtQueryInformationProcess NativeWinApi::NtQueryInformationProcess = nullptr;
def_NtQueryInformationThread NativeWinApi::NtQueryInformationThread = nullptr;
def_NtQuerySystemInformation NativeWinApi::NtQuerySystemInformation = nullptr;
def_NtQueryVirtualMemory NativeWinApi::NtQueryVirtualMemory = nullptr;
def_NtResumeProcess NativeWinApi::NtResumeProcess = nullptr;
def_NtResumeThread NativeWinApi::NtResumeThread = nullptr;
def_NtSetInformationThread NativeWinApi::NtSetInformationThread = nullptr;
def_NtSuspendProcess NativeWinApi::NtSuspendProcess = nullptr;
def_NtTerminateProcess NativeWinApi::NtTerminateProcess = nullptr;

def_NtOpenSymbolicLinkObject NativeWinApi::NtOpenSymbolicLinkObject = nullptr;
def_NtQuerySymbolicLinkObject NativeWinApi::NtQuerySymbolicLinkObject = nullptr;

def_RtlNtStatusToDosError NativeWinApi::RtlNtStatusToDosError = nullptr;
def_NtClose NativeWinApi::NtClose = nullptr;

void NativeWinApi::initialize()
{
    if (RtlNtStatusToDosError)
    {
        return;
    }

    const auto hModuleNtdll = GetModuleHandle(TEXT("ntdll.dll"));

	if (!hModuleNtdll)
	{
		return;
	}

	NtCreateThreadEx = reinterpret_cast<def_NtCreateThreadEx>(GetProcAddress(hModuleNtdll, "NtCreateThreadEx"));
	NtDuplicateObject = reinterpret_cast<def_NtDuplicateObject>(GetProcAddress(hModuleNtdll, "NtDuplicateObject"));
	NtOpenProcess = reinterpret_cast<def_NtOpenProcess>(GetProcAddress(hModuleNtdll, "NtOpenProcess"));
	NtOpenThread = reinterpret_cast<def_NtOpenThread>(GetProcAddress(hModuleNtdll, "NtOpenThread"));
	NtQueryObject = reinterpret_cast<def_NtQueryObject>(GetProcAddress(hModuleNtdll, "NtQueryObject"));
	NtQueryInformationFile = reinterpret_cast<def_NtQueryInformationFile>(GetProcAddress(hModuleNtdll, "NtQueryInformationFile"));
	NtQueryInformationProcess = reinterpret_cast<def_NtQueryInformationProcess>(GetProcAddress(hModuleNtdll, "NtQueryInformationProcess"));
	NtQueryInformationThread = reinterpret_cast<def_NtQueryInformationThread>(GetProcAddress(hModuleNtdll, "NtQueryInformationThread"));
	NtQuerySystemInformation = reinterpret_cast<def_NtQuerySystemInformation>(GetProcAddress(hModuleNtdll, "NtQuerySystemInformation"));
	NtQueryVirtualMemory = reinterpret_cast<def_NtQueryVirtualMemory>(GetProcAddress(hModuleNtdll, "NtQueryVirtualMemory"));
	NtResumeProcess = reinterpret_cast<def_NtResumeProcess>(GetProcAddress(hModuleNtdll, "NtResumeProcess"));
	NtResumeThread = reinterpret_cast<def_NtResumeThread>(GetProcAddress(hModuleNtdll, "NtResumeThread"));
	NtSetInformationThread = reinterpret_cast<def_NtSetInformationThread>(GetProcAddress(hModuleNtdll, "NtSetInformationThread"));
	NtSuspendProcess = reinterpret_cast<def_NtSuspendProcess>(GetProcAddress(hModuleNtdll, "NtSuspendProcess"));
	NtTerminateProcess = reinterpret_cast<def_NtTerminateProcess>(GetProcAddress(hModuleNtdll, "NtTerminateProcess"));
    NtOpenSymbolicLinkObject = reinterpret_cast<def_NtOpenSymbolicLinkObject>(GetProcAddress(hModuleNtdll, "NtOpenSymbolicLinkObject"));
    NtQuerySymbolicLinkObject = reinterpret_cast<def_NtQuerySymbolicLinkObject>(GetProcAddress(hModuleNtdll, "NtQuerySymbolicLinkObject"));

	RtlNtStatusToDosError = reinterpret_cast<def_RtlNtStatusToDosError>(GetProcAddress(hModuleNtdll, "RtlNtStatusToDosError"));
    NtClose = reinterpret_cast<def_NtClose>(GetProcAddress(hModuleNtdll, "NtClose"));
}


PPEB NativeWinApi::getCurrentProcessEnvironmentBlock()
{
	return getProcessEnvironmentBlockAddress(GetCurrentProcess());
}

PPEB NativeWinApi::getProcessEnvironmentBlockAddress(HANDLE processHandle)
{
	ULONG lReturnLength = 0;
	PROCESS_BASIC_INFORMATION processBasicInformation;

	if (NtQueryInformationProcess(processHandle,ProcessBasicInformation,&processBasicInformation,sizeof(PROCESS_BASIC_INFORMATION),&lReturnLength) >= 0 && lReturnLength == sizeof(PROCESS_BASIC_INFORMATION))
	{
		//printf("NtQueryInformationProcess success %d\n",sizeof(PROCESS_BASIC_INFORMATION));

		return processBasicInformation.PebBaseAddress;
	}
	else
	{
		//printf("NtQueryInformationProcess failed %d vs %d\n",lReturnLength,sizeof(PROCESS_BASIC_INFORMATION));
		return nullptr;
	}
}