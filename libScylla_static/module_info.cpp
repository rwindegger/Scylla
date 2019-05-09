#include "module_info.h"
#include "libscylla.h"
#include <Windows.h>
#include <tchar.h>
#include "StringConversion.h"

module_info::module_info(std::shared_ptr<libscylla> context)
    : context_{ std::move(context) }
{}

std::filesystem::path module_info::full_path() const
{
    return full_path_;
}
void module_info::full_path(const std::filesystem::path &full_path)
{
    full_path_ = full_path;
}
std::filesystem::path module_info::filename() const
{
    return full_path_.filename();
}

uintptr_t module_info::base_address() const
{
    return base_address_;
}
void module_info::base_address(const uintptr_t base_address)
{
    base_address_ = base_address;
}

size_t module_info::base_size() const
{
    return base_size_;
}
void module_info::base_size(const size_t base_size)
{
    base_size_ = base_size;
}

bool module_info::is_already_parsed() const
{
    return is_already_parsed_;
}
void module_info::is_already_parsed(const bool is_already_parsed)
{
    is_already_parsed_ = is_already_parsed;
}

bool module_info::is_parsing() const
{
    return is_parsing_;
}
void module_info::is_parsing(const bool is_parsing)
{
    is_parsing_ = is_parsing;
}

int module_info::priority() const
{
    return priority_;
}
void module_info::priority(const int priority)
{
    priority_ = priority;
}
void module_info::set_priority()
{
    TCHAR module_file_name[MAX_PATH];
    StringConversion::ToTStr(filename().c_str(), module_file_name, _countof(module_file_name));
    
    //imports by kernelbase don't exist
    if (!_tcsicmp(module_file_name, TEXT("kernelbase.dll")))
    {
        priority(-1);
    }
    else if (!_tcsicmp(module_file_name, TEXT("ntdll.dll")))
    {
        priority(0);
    }
    else if (!_tcsicmp(module_file_name, TEXT("shlwapi.dll")))
    {
        priority(0);
    }
    else if (!_tcsicmp(module_file_name, TEXT("ShimEng.dll")))
    {
        priority(0);
    }
    else if (!_tcsicmp(module_file_name, TEXT("kernel32.dll")))
    {
        priority(2);
    }
    else if (!_tcsnicmp(module_file_name, TEXT("API-"), 4) || !_tcsnicmp(module_file_name, TEXT("EXT-"), 4)) //API_SET_PREFIX_NAME, API_SET_EXTENSION
    {
        priority(0);
    }
    else
    {
        priority(1);
    }
}

bool module_info::is_in_winsxs() const
{
    TCHAR module_file_name[MAX_PATH];
    StringConversion::ToTStr(full_path().c_str(), module_file_name, _countof(module_file_name));
    if (_tcsstr(module_file_name, TEXT("\\WinSxS\\")))
    {
        return true;
    }

    if (_tcsstr(module_file_name, TEXT("\\winsxs\\")))
    {
        return true;
    }

    return false;
}
bool module_info::is_loaded_local() const
{
    TCHAR module_file_name[MAX_PATH];
    StringConversion::ToTStr(full_path().c_str(), module_file_name, _countof(module_file_name));
    for (auto& i : *context_->local_modules())
    {
        TCHAR local_name[MAX_PATH];
        StringConversion::ToTStr(i->full_path().c_str(), local_name, _countof(local_name));
        if (!_tcsicmp(module_file_name, local_name))
        {
            //printf("isModuleLoadedInOwnProcess :: %s %s\n",module->fullPath,ownModuleList[i].fullPath);
            return true;
        }
    }
    return false;
}

void module_info::append(std::shared_ptr<api_info> api)
{
    api_list_.push_back(api);
}
