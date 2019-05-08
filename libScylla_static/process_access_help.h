#pragma once
#include "scylla_types.h"

#include <windows.h>
#include <vector>
#include <distorm.h>

#define PE_HEADER_BYTES_COUNT (0x1024)

// The number of the array of instructions the decoder function will use to return the disassembled instructions.
// Play with this value for performance...
#define MAX_INSTRUCTIONS (200)

#ifdef _WIN64
#define SCYLLA_DECODE_TYPE Decode64Bits;
#else
#define SCYLLA_DECODE_TYPE Decode32Bits;
#endif

enum class decompose_status
{
    success = 0,
    error = 1,
};

struct decompose_state
{
    decompose_status status;
    _CodeInfo code_info;
    std::vector<_DInst> instructions;
};

class process_access_help
{
public:
    explicit process_access_help(const std::shared_ptr<libscylla>& context);
    explicit process_access_help(const std::shared_ptr<libscylla>& context, pid_t target_pid);
    bool get_process_modules(std::vector<std::shared_ptr<module_info>> &moduleList);
    size_t get_size_of_image_process(uintptr_t moduleBase);
    size_t get_size_of_image_process_native(uintptr_t moduleBase);

    bool read_remote_memory(uintptr_t address, LPVOID dataBuffer, size_t size);
    bool write_remote_memory(uintptr_t address, LPVOID dataBuffer, size_t size);

    decompose_state decompose_memory(uintptr_t address, LPVOID dataBuffer, size_t bufferSize);
private:
    bool open_process(pid_t pid);
    HANDLE open_process_native(DWORD dwDesiredAccess, pid_t szPID) const;
protected:
    LPVOID create_file_mapping_view_read(LPCTSTR filePath) const;
    LPVOID create_file_mapping_view_full(LPCTSTR filePath) const;
    LPVOID create_file_mapping_view(LPCTSTR filePath, DWORD accessFile, DWORD flProtect, DWORD accessMap) const;
    bool get_memory_region_from_address(uintptr_t address, uintptr_t* memory_region_base, size_t* memory_region_size);

    static bool is_page_executable(DWORD Protect);
    static bool is_page_accessable(DWORD Protect);

    std::shared_ptr<libscylla> context_;
    HANDLE process_{ nullptr };
    uintptr_t target_image_base_{};
    size_t target_image_size_{};
    uintptr_t max_valid_address_{};
};
