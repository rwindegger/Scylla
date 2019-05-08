#include "api_info.h"
#include <tchar.h>
#include <VersionHelpers.h>

bool api_info::is_api_blacklisted(LPCTSTR name)
{
    if (!IsWindowsVistaOrGreater())
    {
        return 0 != _tcscmp(name, TEXT("RestoreLastError"));
    }

    return false;
}

bool api_info::is_api_forwarded(intptr_t rva, PIMAGE_NT_HEADERS pNtHeader)
{
    return rva > pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
        rva < pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress +
        pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
}

LPCTSTR api_info::name() const
{
    return name_;
}

void api_info::name(LPCTSTR name)
{
    _tcscpy_s(name_, _countof(name_), name);
}

std::shared_ptr<module_info> api_info::module() const
{
    return module_;
}

uint16_t api_info::hint() const
{
    return hint_;
}

void api_info::hint(uint16_t hint)
{
    hint_ = hint;
}

uintptr_t api_info::va() const
{
    return va_;
}

void api_info::va(uintptr_t va)
{
    va_ = va;
}

intptr_t api_info::rva() const
{
    return rva_;
}

void api_info::rva(uintptr_t rva)
{
    rva_ = rva;
}

uint16_t api_info::ordinal() const
{
    return ordinal_;
}

void api_info::ordinal(uint16_t ordinal)
{
    ordinal_ = ordinal;
}

bool api_info::is_forwarded() const
{
    return is_forwarded_;
}

void api_info::is_forwarded(bool is_forwarded)
{
    is_forwarded_ = is_forwarded;
}
