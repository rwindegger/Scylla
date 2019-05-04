#pragma once

#include <windows.h>

// Abstract class for logging text.
class Logger
{
public:
    virtual ~Logger() = default;
    virtual void log(const WCHAR * format, ...);
    virtual void log(const CHAR * format, ...);
protected:
    virtual void write(const WCHAR * str) = 0;
    virtual void write(const CHAR * str);
};

class ConsoleLogger : public Logger
{
public:
    ConsoleLogger() = default;
protected:
    void write(const WCHAR* str) override;
    void write(const CHAR* str) override;
};

// Dummy logger which does absolutely nothing
class DummyLogger : public Logger
{
public:
    DummyLogger() = default;
private:
    void write(const WCHAR *str) override {};
    void write(const CHAR *str) override {};
};

class FileLog : public Logger
{
public:
    FileLog(const WCHAR * fileName);

private:
    void write(const WCHAR * str) override;
    void write(const CHAR * str) override;

    WCHAR filePath[MAX_PATH];
};
