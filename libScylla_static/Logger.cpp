#include "Logger.h"

#include <iostream>
#include <shlwapi.h>
#include <cstdio>
#include <atlbase.h> 
#include <atlconv.h>

void Logger::log(LPCTSTR format, ...)
{
	static TCHAR buf[300];

	if(!format)
		return;

	va_list va_alist;
	va_start (va_alist, format);
	_vsntprintf_s(buf, _countof(buf) - 1, format, va_alist);
	va_end (va_alist);

	write(buf);
}

void ConsoleLogger::write(LPCTSTR str)
{
    _tprintf_s(TEXT("[SCYLLA] %s\r\n"), str);
}

FileLog::FileLog(LPCTSTR fileName)
{
	GetModuleFileName(0, this->filePath, _countof(this->filePath));
	PathRemoveFileSpec(this->filePath);
	PathAppend(this->filePath, fileName);
}

void FileLog::write(LPCTSTR str)
{
	FILE * pFile = 0;
	if (_tfopen_s(&pFile, filePath, TEXT("a")) == 0)
	{
		_fputts(str, pFile);
        _fputts(TEXT("\r\n"), pFile);
		fclose(pFile);
	}
}
