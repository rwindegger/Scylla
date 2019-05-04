#pragma once
#include "Logger.h"

class ListboxLog : public Logger
{
public:

    ListboxLog() : window(0) { }
    ListboxLog(HWND window);

    void setWindow(HWND window);

private:

    void write(const WCHAR * str);
    //void write(const CHAR * str);

    HWND window;
};
