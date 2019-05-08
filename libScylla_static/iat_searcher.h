#pragma once
#include "scylla_types.h"
#include "api_reader.h"

#include <Windows.h>

class iat_searcher
    : public api_reader
{
public:
    explicit iat_searcher(const std::shared_ptr<libscylla>& context);
    explicit iat_searcher(const std::shared_ptr<libscylla>& context, pid_t target_pid);

    bool search_import_address_table_remote(uintptr_t start_address, uintptr_t* iat_address, size_t* iat_size, bool advanced = false);
private:
    uintptr_t find_api_address_in_iat(uintptr_t startAddress);

    bool find_iat_advanced(uintptr_t start_address, uintptr_t* iat_address, size_t* iat_size);
    
    bool is_iat_pointer_valid(uintptr_t iat_pointer, bool checkRedirects, uintptr_t *memory_address, size_t *memory_size);
    uintptr_t find_iat_pointer(decompose_state &state) const;
    void find_iat_pointers(decompose_state &state, std::set<uintptr_t> &iat_pointers);
    void filter_iat_pointers_list(std::set<uintptr_t> & iat_pointers);

    bool find_iat_start_and_size(uintptr_t start_address, uintptr_t* iat_address, size_t* iat_size);
    uintptr_t find_iat_start_address(uintptr_t base_address, uintptr_t start_address, LPVOID data_buffer, size_t buffer_size) const;
    size_t find_iat_size(uintptr_t base_address, uintptr_t iat_address, LPVOID data_buffer, size_t buffer_size);

    uintptr_t find_next_function_address(decompose_state &state) const;
    void find_executable_memory_pages_by_start_address(uintptr_t start_address, uintptr_t* base_address, size_t* memory_size);

    void get_memory_base_and_size_for_iat(uintptr_t address, uintptr_t* base_address, size_t* base_size) const;
};
