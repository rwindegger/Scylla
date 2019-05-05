#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <psapi.h>

#include "NativeWinApi.h"
#include "DeviceNameResolver.h"

typedef BOOL (WINAPI *def_IsWow64Process)(HANDLE hProcess,PBOOL Wow64Process);

class Process {
public:
	size_t PID;
    DWORD sessionId{};
	intptr_t imageBase{};
	intptr_t pebAddress{};
	DWORD entryPoint{}; //RVA without imagebase
	DWORD imageSize{};
	TCHAR filename[MAX_PATH]{};
	TCHAR fullPath[MAX_PATH]{};

	Process()
	{
		PID = 0;
	}
};

enum ProcessType {
	PROCESS_UNKNOWN,
	PROCESS_MISSING_RIGHTS,
	PROCESS_32,
	PROCESS_64
};

class ProcessLister {
public:

	static def_IsWow64Process _IsWow64Process;

	ProcessLister()
	{
		deviceNameResolver = new DeviceNameResolver();
		_IsWow64Process = reinterpret_cast<def_IsWow64Process>(GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "IsWow64Process"));
	}
	~ProcessLister()
	{
		delete deviceNameResolver;
	}

	std::vector<Process>& getProcessList();
	static bool isWindows64();
	static DWORD setDebugPrivileges();
    std::vector<Process>& getProcessListSnapshotNative();
private:
	std::vector<Process> processList;

	DeviceNameResolver * deviceNameResolver;

    static ProcessType checkIsProcess64(HANDLE hProcess);

	bool getAbsoluteFilePath(HANDLE hProcess, Process * process) const;


    void handleProcessInformationAndAddToList( PSYSTEM_PROCESS_INFORMATION pProcess );
    static void getProcessImageInformation( HANDLE hProcess, Process* process );
    static DWORD_PTR getPebAddressFromProcess( HANDLE hProcess );
};