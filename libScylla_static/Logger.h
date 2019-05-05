#pragma once

#include <windows.h>

// Abstract class for logging text.
class Logger
{
public:
    virtual ~Logger() = default;
    virtual void log(LPCTSTR format, ...);
protected:
    virtual void write(LPCTSTR str) = 0;
};

class ConsoleLogger : public Logger
{
public:
    ConsoleLogger() = default;
protected:
    void write(LPCTSTR str) override;
};

// Dummy logger which does absolutely nothing
class DummyLogger : public Logger
{
public:
    DummyLogger() = default;
private:
    void write(LPCTSTR str) override {};
};

class FileLog : public Logger
{
public:
    FileLog(LPCTSTR fileName);
private:
    void write(LPCTSTR str) override;

    TCHAR filePath[MAX_PATH]{};
};
