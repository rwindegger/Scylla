#include "ListboxLog.h"
#include <shlwapi.h>
#include <atlbase.h>

void ListboxLog::setWindow(HWND window)
{
    this->window = window;
}

void ListboxLog::write(const WCHAR* str)
{
    LRESULT index = SendMessageW(window, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(str));
    SendMessage(window, LB_SETCURSEL, index, 0);
    UpdateWindow(window);
}
