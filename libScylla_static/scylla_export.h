#pragma once

#if defined (WIN32)
#if defined (_MSC_VER)
#define SCYLLA_DECL_API _cdecl
#pragma warning(disable: 4251)
#endif
#if defined(libScylla_EXPORTS)
#define  SCYLLA_DLL_EXPORT __declspec(dllexport)
#else
#define  SCYLLA_DLL_EXPORT  /*__declspec(dllimport)*/
#endif
#else
#define SCYLLA_DLL_EXPORT 
#endif
