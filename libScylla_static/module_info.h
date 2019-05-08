#pragma once
#include "scylla_types.h"

#include <filesystem>

class module_info
{
public:
    explicit module_info(std::shared_ptr<libscylla> context);

    std::filesystem::path full_path() const;
    void full_path(const std::filesystem::path &full_path);
    std::filesystem::path filename() const;

    uintptr_t base_address() const;
    void base_address(uintptr_t base_address);

    size_t base_size() const;
    void base_size(size_t base_size);

    bool is_already_parsed() const;
    void is_already_parsed(bool is_already_parsed);

    bool is_parsing() const;
    void is_parsing(bool is_parsing);

    int priority() const;
    void priority(int priority);
    void set_priority();

    bool is_in_winsxs() const;
    bool is_loaded_local() const;

    void append(std::shared_ptr<api_info> api);

private:
    std::shared_ptr<libscylla> context_{};
    std::filesystem::path full_path_{};
    uintptr_t base_address_{};
    size_t base_size_{};

    bool is_already_parsed_{};
    bool is_parsing_{};

    /*
      for iat rebuilding with duplicate entries:

      ntdll = low priority
      kernelbase = low priority
      SHLWAPI = low priority

      kernel32 = high priority

      priority = 1 -> normal/high priority
      priority = 0 -> low priority
    */
    int priority_{};

    std::vector<std::shared_ptr<api_info>> api_list_{};
};