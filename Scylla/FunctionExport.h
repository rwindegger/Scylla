#pragma once

#include <windows.h>

#if defined (WIN32)
#if defined (_MSC_VER)
#pragma warning(disable: 4251)
#endif
#if defined(ScyllaDll_EXPORTS)
#define  SCYLLA_DLL_EXPORT __declspec(dllexport)
#else
#define  SCYLLA_DLL_EXPORT  __declspec(dllimport)
#endif
#else
#define SCYLLA_DLL_EXPORT 
#endif

const int SCY_ERROR_SUCCESS = 0;
const int SCY_ERROR_PROCOPEN = -1;
const int SCY_ERROR_IATWRITE = -2;
const int SCY_ERROR_IATSEARCH = -3;
const int SCY_ERROR_IATNOTFOUND = -4;
const int SCY_ERROR_PIDNOTFOUND = -5;


typedef struct _GUI_DLL_PARAMETER {
	DWORD dwProcessId;
	HINSTANCE mod;
	DWORD_PTR entrypoint;
} GUI_DLL_PARAMETER, *PGUI_DLL_PARAMETER;

int InitializeGui(HINSTANCE hInstance, LPARAM param);

#ifdef __cplusplus
extern "C" { 
#endif

//function to export in DLL

SCYLLA_DLL_EXPORT  BOOL DumpProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult);

SCYLLA_DLL_EXPORT  BOOL WINAPI ScyllaDumpCurrentProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult);
SCYLLA_DLL_EXPORT  BOOL WINAPI ScyllaDumpCurrentProcessA(const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult);

SCYLLA_DLL_EXPORT  BOOL WINAPI ScyllaDumpProcessW(DWORD_PTR pid, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult);
SCYLLA_DLL_EXPORT  BOOL WINAPI ScyllaDumpProcessA(DWORD_PTR pid, const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult);

SCYLLA_DLL_EXPORT  BOOL WINAPI ScyllaRebuildFileW(const WCHAR * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);
SCYLLA_DLL_EXPORT  BOOL WINAPI ScyllaRebuildFileA(const char * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);

SCYLLA_DLL_EXPORT  const WCHAR * WINAPI ScyllaVersionInformationW();
SCYLLA_DLL_EXPORT  const char * WINAPI ScyllaVersionInformationA();

SCYLLA_DLL_EXPORT  DWORD WINAPI ScyllaVersionInformationDword();

SCYLLA_DLL_EXPORT  int WINAPI ScyllaStartGui(DWORD dwProcessId, HINSTANCE mod, DWORD_PTR entrypoint);

SCYLLA_DLL_EXPORT  int WINAPI ScyllaIatSearch(DWORD dwProcessId, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch);
SCYLLA_DLL_EXPORT  int WINAPI ScyllaIatFixAutoW(DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR * dumpFile, const WCHAR * iatFixFile);

#ifdef __cplusplus
}
#endif

/*
C/C++ Prototyps

typedef const WCHAR * (WINAPI * def_ScyllaVersionInformationW)();
typedef const char * (WINAPI * def_ScyllaVersionInformationA)();
typedef DWORD (WINAPI * def_ScyllaVersionInformationDword)();
typedef int (WINAPI * def_ScyllaIatSearch)(DWORD dwProcessId, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch);
typedef int (WINAPI * def_ScyllaStartGui)(DWORD dwProcessId, HINSTANCE mod);

*/
