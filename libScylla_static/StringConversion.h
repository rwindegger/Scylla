#pragma once
#include <atlbase.h>

class StringConversion
{
public:
    static LPCSTR ToCStr(LPCTSTR str, LPSTR buf, size_t bufsize);
    static LPCWSTR ToWStr(LPCTSTR str, LPWSTR buf, size_t bufsize);
    static LPCTSTR ToTStr(LPCSTR str, LPTSTR buf, size_t bufsize);
    static LPCTSTR ToTStr(LPCWSTR str, LPTSTR buf, size_t bufsize);
};
