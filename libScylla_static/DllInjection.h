#pragma once

#include <windows.h>

class DllInjection
{
public:

    static HMODULE dllInjection(HANDLE hProcess, LPCTSTR filename);
    static bool unloadDllInProcess(HANDLE hProcess, HMODULE hModule);
    static HANDLE startRemoteThread(HANDLE hProcess, LPCVOID lpStartAddress, LPCVOID lpParameter);

private:

    static HANDLE customCreateRemoteThread(HANDLE hProcess, LPCVOID lpStartAddress, LPCVOID lpParameter);
    static void specialThreadSettings(HANDLE hThread);
    static HMODULE getModuleHandleByFilename(HANDLE hProcess, LPCTSTR filename);
};
