#pragma once

#include <windows.h>
#include <iostream>

// Abstract class for logging text.
class Logger
{
public:

    virtual void log(const WCHAR * format, ...);
    virtual void log(const CHAR * format, ...);

protected:

    virtual void write(const WCHAR * str) = 0;
    virtual void write(const CHAR * str);
};

class ConsoleLogger : public Logger
{
public:
    ConsoleLogger() {};
    void setWindow(HWND window) {};
protected:
    void write(const WCHAR* str) override { std::wcout << L"[SCYLLA] " << str << L"\n"; };
};

// Dummy logger which does absolutely nothing
class DummyLogger : public Logger
{
public:
    DummyLogger() {};
private:
    void write(const WCHAR * str) {};
};

class FileLog : public Logger
{
public:

    FileLog(const WCHAR * fileName);

private:

    void write(const WCHAR * str);
    void write(const CHAR * str);

    WCHAR filePath[MAX_PATH];
};
