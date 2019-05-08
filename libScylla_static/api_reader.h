#pragma once
#include "scylla_types.h"
#include "process_access_help.h"

#include <Windows.h>

class api_reader
    : public process_access_help
{
public:
    explicit api_reader(const std::shared_ptr<libscylla>& context);
    explicit api_reader(const std::shared_ptr<libscylla>& context, pid_t target_pid);
    void read_apis_from_module_list(std::vector<std::shared_ptr<module_info>> &modules, std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& apis);
    void read_and_parse_iat(uintptr_t addressIAT, size_t sizeIAT, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new);
    bool is_api_address_valid(uintptr_t virtual_address) const;
    std::shared_ptr<api_info> get_api_by_virtual_address(uintptr_t virtualAddress, bool* isSuspect);
protected:
    friend class libscylla;
    void parse_module(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module);
    void parse_module_mapping(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module);
    void parse_module_local(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module);
    void parse_module_remote(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module);

    bool is_pe_and_export_table_valid(PIMAGE_NT_HEADERS pNtHeader);
    void parse_export_table(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_EXPORT_DIRECTORY pExportDir, intptr_t deltaAddress);

    uint8_t* get_header_from_process(const std::shared_ptr<module_info>& module);
    uint8_t* get_export_table_from_process(const std::shared_ptr<module_info>& module, PIMAGE_NT_HEADERS pNtHeader);
        
    void set_min_max_api_address(uintptr_t virtual_address);

    void add_api(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, std::shared_ptr<module_info> module, LPCTSTR functionName, uint16_t hint, uint16_t ordinal, uintptr_t va, intptr_t rva, bool is_forwarded);
    void add_api(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, std::shared_ptr<module_info> module, uint16_t ordinal, uintptr_t va, intptr_t rva, bool is_forwarded);

    void handle_forwarded_api(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& parent_module, uintptr_t vaStringPointer, LPCTSTR functionNameParent, intptr_t rvaParent, uint16_t ordinalParent);
    bool is_invalid_memory_for_iat(uintptr_t address) const;

    std::shared_ptr<module_info> find_module_by_name(LPCTSTR name) const;

    void find_api_by_module(const std::shared_ptr<module_info>& module, uint16_t ordinal, uintptr_t* vaApi, intptr_t* rvaApi);
    void find_api_by_module(const std::shared_ptr<module_info>& module, LPCTSTR searchFunctionName, uintptr_t* vaApi, intptr_t* rvaApi);
    void find_api_by_module(const std::shared_ptr<module_info>& module, LPCTSTR searchFunctionName, uint16_t ordinal, uintptr_t* vaApi, intptr_t* rvaApi);
    void find_api_by_module_remote(const std::shared_ptr<module_info>& module, LPCTSTR searchFunctionName, uint16_t ordinal, uintptr_t* vaApi, intptr_t* rvaApi);
    bool find_api_in_export_table(const std::shared_ptr<module_info>& module, PIMAGE_EXPORT_DIRECTORY pExportDir, intptr_t deltaAddress, LPCTSTR searchFunctionName, uint16_t ordinal, uintptr_t * vaApi, intptr_t * rvaApi);

    void parse_iat(uintptr_t addressIAT, uint8_t* iatBuffer, size_t size, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new);
    std::shared_ptr<api_info> get_scored_api(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>::const_iterator it1, size_t count_duplicates, bool has_name, bool has_unicode_ansi_name, bool has_no_underline_in_name, bool has_prio_dll, bool has_prio0_dll, bool has_prio1_dll, bool has_prio2_dll, bool first_win);

    void add_found_api_to_module_list(uintptr_t iatAddress, const std::shared_ptr<api_info>& api_found, bool isNewModule, bool isSuspect, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new);
    bool add_not_found_api_to_module_list(uintptr_t iatAddressVA, uintptr_t apiAddress, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new);

    void add_module_to_module_list(LPCTSTR moduleName, uintptr_t firstThunk, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new);
    void add_unknown_module_to_module_list(uintptr_t firstThunk, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new);

    bool api_reader::add_function_to_module_list(const std::shared_ptr<api_info>& api_found, uintptr_t va, intptr_t rva, uint16_t ordinal, bool valid, bool suspect, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new);
private:
    uintptr_t min_api_address_;
    uintptr_t max_api_address_;
    std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>> api_list_;
};
