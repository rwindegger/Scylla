#pragma once
#include "scylla_types.h"

#include <windows.h>

class api_info
{
public:
    static bool is_api_blacklisted(LPCTSTR name);
    static bool is_api_forwarded(intptr_t rva, PIMAGE_NT_HEADERS pNtHeader);

    api_info(std::shared_ptr<module_info> module)
        : module_{ module }
    {}

    LPCTSTR name() const;
    void name(LPCTSTR name);

    std::shared_ptr<module_info> module() const;

    uint16_t hint() const;
    void hint(uint16_t hint);
    
    uintptr_t va() const;
    void va(uintptr_t va);
    
    intptr_t rva() const;
    void rva(uintptr_t rva);

    uint16_t ordinal() const;
    void ordinal(uint16_t ordinal);

    bool is_forwarded() const;
    void is_forwarded(bool is_forwarded);
private:
    TCHAR name_[MAX_PATH]{};
    uint16_t hint_{};
    uintptr_t va_{};
    intptr_t rva_{};
    uint16_t ordinal_{};
    bool is_forwarded_{};
    std::shared_ptr<module_info> module_{ nullptr };
};