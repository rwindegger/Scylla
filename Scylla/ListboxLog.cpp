#include "ListboxLog.h"
#include <shlwapi.h>
#include <atlbase.h>

ListboxLog::ListboxLog(HWND window)
    : window(window)
{
}

void ListboxLog::setWindow(HWND window)
{
    this->window = window;
}

void ListboxLog::write(LPCTSTR str)
{
    const LRESULT index = SendMessage(window, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(str));
    SendMessage(window, LB_SETCURSEL, index, 0);
    UpdateWindow(window);
}
