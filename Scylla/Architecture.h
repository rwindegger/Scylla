#pragma once

#include <windows.h>

#ifdef _WIN64
#define ARCHITECTURE_S          "x64"
#else
#define ARCHITECTURE_S          "x86"
#endif
#define ARCHITECTURE          TEXT(ARCHITECTURE_S)

#if defined(_MSC_VER) && _MSC_VER >= 1800
#include <inttypes.h>
#endif

// Using inttypes string formating if possible (VS2015 and greater)
#if defined(_MSC_VER) && _MSC_VER >= 1900
#define PRINTF_DWORD_PTR      TEXT("%" PRIxPTR)
#define PRINTF_DWORD_PTR_FULL TEXT("%" PRIxPTR)
#define PRINTF_DWORD_PTR_HALF TEXT("%" PRIxPTR)
#define PRINTF_INTEGER        TEXT("%" PRIuMAX)
#else

#ifdef _WIN64
#define PRINTF_DWORD_PTR_S      "%I64X"
#define PRINTF_DWORD_PTR_FULL_S "%016I64X"
#define PRINTF_DWORD_PTR_HALF_S "%08I64X"
#define PRINTF_INTEGER_S        "%I64u"
#else
#define PRINTF_DWORD_PTR_S      "%X"
#define PRINTF_DWORD_PTR_FULL_S "%08X"
#define PRINTF_DWORD_PTR_HALF_S "%08X"
#define PRINTF_INTEGER_S        "%u"
#endif

#define PRINTF_DWORD_PTR      TEXT(PRINTF_DWORD_PTR_S)
#define PRINTF_DWORD_PTR_FULL TEXT(PRINTF_DWORD_PTR_FULL_S)
#define PRINTF_DWORD_PTR_HALF TEXT(PRINTF_DWORD_PTR_HALF_S)
#define PRINTF_INTEGER        TEXT(PRINTF_INTEGER_S)
#endif

