#pragma once
#include <windows.h>

/* Scylla current context. */
typedef size_t SCY_HANDLE, *PSCY_HANDLE;

typedef const WCHAR * (WINAPIV * def_ScyllaVersionInformationW)();
typedef const char * (WINAPIV * def_ScyllaVersionInformationA)();
typedef DWORD (WINAPIV * def_ScyllaVersionInformationDword)();

typedef int (WINAPIV * def_ScyllaIatSearch)(SCY_HANDLE phCtxt, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch);
typedef int (WINAPIV * def_ScyllaStartGui)(SCY_HANDLE phCtxt, HINSTANCE mod);

typedef  BOOL (WINAPIV * def_ScyllaInitContext)(PSCY_HANDLE phCtxt, DWORD_PTR TargetProcessPid);
typedef  BOOL (WINAPIV * def_ScyllaUnInitContext)(SCY_HANDLE hCtxt);

typedef struct SCYLLA_DLL_T {
	HMODULE hScyllaDll;
	def_ScyllaVersionInformationW VersionInformationW;
	def_ScyllaVersionInformationA VersionInformationA;
	def_ScyllaVersionInformationDword VersionInformationDword;
	def_ScyllaIatSearch ScyllaIatSearch;
	def_ScyllaStartGui  ScyllaStartGui;
	def_ScyllaInitContext ScyllaInitContext;
	def_ScyllaUnInitContext ScyllaUnInitContext;
} SCYLLA_DLL;

bool ScyllaLoadDll(LPCTSTR ScyllaDllPath, SCYLLA_DLL *pScyllaDllObject);

void ScyllaUnloadDll(SCYLLA_DLL *pScyllaDllObject);
