#pragma once
#include <windows.h>
#include <stdbool.h>

typedef const WCHAR * (WINAPIV * def_ScyllaVersionInformationW)();
typedef const char * (WINAPIV * def_ScyllaVersionInformationA)();
typedef DWORD (WINAPIV * def_ScyllaVersionInformationDword)();

typedef int (WINAPIV * def_ScyllaIatSearch)(DWORD dwProcessId, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch);
typedef int (WINAPIV * def_ScyllaStartGui)(DWORD dwProcessId, HINSTANCE mod);

typedef struct SCYLLA_DLL_T {
	HMODULE hScyllaDll;
	def_ScyllaVersionInformationW VersionInformationW;
	def_ScyllaVersionInformationA VersionInformationA;
	def_ScyllaVersionInformationDword VersionInformationDword;
	def_ScyllaIatSearch ScyllaIatSearch;
	def_ScyllaStartGui  ScyllaStartGui;
} SCYLLA_DLL;

bool ScyllaLoadDll(TCHAR *ScyllaDllPath, SCYLLA_DLL *pScyllaDllObject);

void ScyllaUnloadDll(SCYLLA_DLL *pScyllaDllObject);
