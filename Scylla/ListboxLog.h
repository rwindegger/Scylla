#pragma once
#include "Logger.h"

class ListboxLog : public Logger
{
public:
    ListboxLog() = default;
    explicit ListboxLog(HWND window);
    void setWindow(HWND window);
private:
    void write(const WCHAR * str) override;
    HWND window;
};
