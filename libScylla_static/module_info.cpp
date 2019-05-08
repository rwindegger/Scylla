#include "module_info.h"
#include "libscylla.h"
#include <Windows.h>
#include <tchar.h>

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
    const auto moduleFileName = filename();

    //imports by kernelbase don't exist
    if (!_tcsicmp(moduleFileName.c_str(), TEXT("kernelbase.dll")))
    {
        priority(-1);
    }
    else if (!_tcsicmp(moduleFileName.c_str(), TEXT("ntdll.dll")))
    {
        priority(0);
    }
    else if (!_tcsicmp(moduleFileName.c_str(), TEXT("shlwapi.dll")))
    {
        priority(0);
    }
    else if (!_tcsicmp(moduleFileName.c_str(), TEXT("ShimEng.dll")))
    {
        priority(0);
    }
    else if (!_tcsicmp(moduleFileName.c_str(), TEXT("kernel32.dll")))
    {
        priority(2);
    }
    else if (!_tcsnicmp(moduleFileName.c_str(), TEXT("API-"), 4) || !_tcsnicmp(moduleFileName.c_str(), TEXT("EXT-"), 4)) //API_SET_PREFIX_NAME, API_SET_EXTENSION
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
    if (_tcsstr(full_path_.c_str(), TEXT("\\WinSxS\\")))
    {
        return true;
    }

    if (_tcsstr(full_path_.c_str(), TEXT("\\winsxs\\")))
    {
        return true;
    }

    return false;
}
bool module_info::is_loaded_local() const
{
    for (auto& i : *context_->local_modules())
    {
        if (!_tcsicmp(full_path_.c_str(), i->full_path_.c_str()))
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
