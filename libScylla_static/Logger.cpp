#include "Logger.h"

#include <iostream>
#include <shlwapi.h>
#include <cstdio>
#include <atlbase.h> 
#include <atlconv.h>

void Logger::log(const WCHAR * format, ...)
{
	static WCHAR buf[300];

	if(!format)
		return;

	va_list va_alist;
	va_start (va_alist, format);
	_vsnwprintf_s(buf, _countof(buf) - 1, format, va_alist);
	va_end (va_alist);

	write(buf);
}

void Logger::log(const CHAR * format, ...)
{
#ifdef DEBUG_COMMENTS
	static char buf[300];

	if(!format)
		return;

	va_list va_alist;
	va_start (va_alist, format);
	_vsnprintf_s(buf, _countof(buf) - 1, format, va_alist);
	va_end (va_alist);

	write(buf);
#endif /* DEBUG_COMMENTS */
}

void Logger::write(const CHAR * str)
{
	write(ATL::CA2W(str));
}

void ConsoleLogger::write(const WCHAR* str)
{
    std::wcout << L"[SCYLLA] " << str << std::endl;
}

void ConsoleLogger::write(const CHAR* str)
{
    std::cout << "[SCYLLA] " << str << std::endl;
}

FileLog::FileLog(const WCHAR * fileName)
{
	GetModuleFileName(0, this->filePath, _countof(this->filePath));
	PathRemoveFileSpec(this->filePath);
	PathAppend(this->filePath, fileName);
}

void FileLog::write(const CHAR * str)
{
	FILE * pFile = 0;
	if (_wfopen_s(&pFile, filePath, L"a") == 0)
	{
		fputs(str, pFile);
		fputs("\r\n", pFile);
		fclose(pFile);
	}
}

void FileLog::write(const WCHAR * str)
{
	FILE * pFile = 0;
	if (_wfopen_s(&pFile, filePath, L"a") == 0)
	{
		fputws(str, pFile);
		fputws(L"\r\n", pFile);
		fclose(pFile);
	}
}
