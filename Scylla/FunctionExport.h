#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif


#if defined (WIN32)
#if defined (_MSC_VER)
#define SCYLLA_DECL_API _cdecl
#pragma warning(disable: 4251)
#endif
#if defined(ScyllaDll_EXPORTS)
#define  SCYLLA_DLL_EXPORT __declspec(dllexport)
#else
#define  SCYLLA_DLL_EXPORT  /*__declspec(dllimport)*/
#endif
#else
#define SCYLLA_DLL_EXPORT 
#endif

/* Scylla Dll API error IDs */
const int SCY_ERROR_SUCCESS = 0;
const int SCY_ERROR_PROCOPEN = -1;
const int SCY_ERROR_IATWRITE = -2;
const int SCY_ERROR_IATSEARCH = -3;
const int SCY_ERROR_IATNOTFOUND = -4;
const int SCY_ERROR_PIDNOTFOUND = -5;

/* Scylla current context. */
typedef size_t SCY_HANDLE, *PSCY_HANDLE;

/*
	Init new context for Scylla. Necessary to call it before any other API (except for ScyllaVersionInformation APIs).
	@param phCtxt : pointer to output Scylla context
	@param TargetProcessPid : Unique id of target process
*/
SCYLLA_DLL_EXPORT  BOOL SCYLLA_DECL_API  ScyllaInitContext(PSCY_HANDLE phCtxt, DWORD_PTR TargetProcessPid);

/*
	Free the input Scylla context. Necessary to call it in order to release resources.
	@param hCtxt : input Scylla context to be cleaned up
*/
SCYLLA_DLL_EXPORT  BOOL SCYLLA_DECL_API  ScyllaUnInitContext(SCY_HANDLE hCtxt);
/*
	Dump Current process into a file.
	@param fileToDump : path to output file
	@param imagebase : Process image base (why ??)
	@param entrypoint : Process entry point (or estimated entry point ?)
	@param fileResult :
*/
SCYLLA_DLL_EXPORT  BOOL SCYLLA_DECL_API  ScyllaDumpCurrentProcessW(SCY_HANDLE hScyllaContext, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult);

/*
	Dump Current process into a file.
	@param fileToDump : path to output file
	@param imagebase : Process image base (why ??)
	@param entrypoint : Process entry point (or estimated entry point ?)
	@param fileResult :
*/
SCYLLA_DLL_EXPORT  BOOL SCYLLA_DECL_API  ScyllaDumpCurrentProcessA(SCY_HANDLE hScyllaContext, const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult);

/*
	Dump process by PID into a file.
	@param pid : process unique PID to dump
	@param fileToDump : path to output file
	@param imagebase : Process image base (why ??)
	@param entrypoint : Process entry point (or estimated entry point ?)
	@param fileResult :
*/
SCYLLA_DLL_EXPORT  BOOL SCYLLA_DECL_API  ScyllaDumpProcessW(DWORD_PTR pid, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult);

/*
	Dump process by PID into a file.
	@param pid : process unique PID to dump
	@param fileToDump : path to output file 
	@param imagebase : Process image base (why ??)
	@param entrypoint : Process entry point (or estimated entry point ?)
	@param fileResult : 
*/
SCYLLA_DLL_EXPORT  BOOL SCYLLA_DECL_API  ScyllaDumpProcessA(DWORD_PTR pid, const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult);

/*
	Rebuild PE ?
*/
SCYLLA_DLL_EXPORT  BOOL SCYLLA_DECL_API  ScyllaRebuildFileW(SCY_HANDLE hScyllaContext, const WCHAR * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);

/*
	Rebuild PE ?
*/
SCYLLA_DLL_EXPORT  BOOL SCYLLA_DECL_API  ScyllaRebuildFileA(SCY_HANDLE hScyllaContext, const char * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);

/*
	Return Scylla dll version string;
*/
SCYLLA_DLL_EXPORT  const WCHAR * SCYLLA_DECL_API  ScyllaVersionInformationW();

/*
	Return Scylla dll version string;
*/
SCYLLA_DLL_EXPORT  const char * SCYLLA_DECL_API  ScyllaVersionInformationA();

/*
	Return Scylla dll version integer;
*/
SCYLLA_DLL_EXPORT  DWORD SCYLLA_DECL_API  ScyllaVersionInformationDword();


/*
	Start Scylla Gui from the API.
	@param dwProcessId : process ID to attach to
	@param mod : module instance from chosen processus
	@param entrypoint : process entry point (for IAT search)
*/
SCYLLA_DLL_EXPORT  int SCYLLA_DECL_API  ScyllaStartGui(SCY_HANDLE hScyllaContext, HINSTANCE mod, DWORD_PTR entrypoint);

/*
	Search IAT in the target process 
	@param dwProcessId : target process PID. the calling process must be able to read into target memory (PROCESS_QUERY_INFORMATION and PROCESS_READ_VM)
	@param iatStart : IAT start address if found
	@param iatSize : IAT size if found
	@param searchStart : where to begin the search in the target process. Usually the EntryPoint or OEP.
	@param advancedSearch : bool to do some advanced digging ?

	return 0 if there were no errors encountered.

	If the heuristics didn't found an IAT, iatStart and iatSize are set to 0.
*/
SCYLLA_DLL_EXPORT  int SCYLLA_DECL_API  ScyllaIatSearch(SCY_HANDLE hScyllaContext, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch);


/*
	Scylla AutoFix import address ?
	@param
*/
SCYLLA_DLL_EXPORT  int SCYLLA_DECL_API  ScyllaIatFixAutoW(SCY_HANDLE hScyllaContext, DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR * dumpFile, const WCHAR * iatFixFile);



#ifdef UNICODE
#define ScyllaDumpProcess ScyllaDumpProcessW
#define ScyllaDumpCurrentProcess ScyllaDumpCurrentProcessW
#define ScyllaVersionInformation ScyllaVersionInformationW
#define ScyllaRebuildFile ScyllaRebuildFileW
#else
#define ScyllaDumpProcess ScyllaDumpProcessA
#define ScyllaDumpCurrentProcess ScyllaDumpCurrentProcessA
#define ScyllaVersionInformation ScyllaVersionInformationA
#define ScyllaRebuildFile ScyllaRebuildFileA
#endif  // !UNICODE


#ifdef __cplusplus
}
#endif
