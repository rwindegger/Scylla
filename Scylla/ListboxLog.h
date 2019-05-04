#pragma once
#include "Logger.h"

class ListboxLog : public Logger
{
public:
    ListboxLog() = default;
    explicit ListboxLog(HWND window);
    void setWindow(HWND window);
private:
    void write(LPCTSTR str) override;
    HWND window;
};
