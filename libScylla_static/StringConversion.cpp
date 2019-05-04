#include "StringConversion.h"
#include <atlconv.h>

LPCSTR StringConversion::ToCStr(LPCTSTR str, LPSTR buf, size_t bufsize)
{
#ifdef _UNICODE
    sprintf_s(buf, bufsize, "%S", str);
#else
    _tcscpy_s(buf, bufsize, str);    
#endif
    return buf;
}

LPCWSTR StringConversion::ToWStr(LPCTSTR str, LPWSTR buf, size_t bufsize)
{
#ifdef _UNICODE
    _tcscpy_s(buf, bufsize, str);
#else
    swprintf_s(buf, bufsize, L"%S", str);
#endif
    return buf;
}

LPCTSTR StringConversion::ToTStr(LPCSTR str, LPTSTR buf, size_t bufsize)
{
#ifdef _UNICODE
    _stprintf_s(buf, bufsize, TEXT("%S"), str);
#else
    _tcscpy_s(buf, bufsize, str);
#endif    
    return buf;
}

LPCTSTR StringConversion::ToTStr(LPCWSTR str, LPTSTR buf, size_t bufsize)
{
#ifdef _UNICODE
    _tcscpy_s(buf, bufsize, str);
#else
    _stprintf_s(buf, bufsize, TEXT("%S"), str);
#endif
    return buf;
}
