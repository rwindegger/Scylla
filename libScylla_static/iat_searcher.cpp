#include "iat_searcher.h"
#include "libscylla.h"
#include "Architecture.h"

iat_searcher::iat_searcher(const std::shared_ptr<libscylla>& context)
    : api_reader(context)
{
}

iat_searcher::iat_searcher(const std::shared_ptr<libscylla>& context, pid_t target_pid)
    : api_reader(context, target_pid)
{
}

bool iat_searcher::search_import_address_table_remote(uintptr_t start_address, uintptr_t* iat_address, size_t* iat_size, bool advanced)
{
    *iat_address = 0;
    *iat_size = 0;

    if (advanced)
    {
        return find_iat_advanced(start_address, iat_address, iat_size);
    }

    const uintptr_t address_in_iat = find_api_address_in_iat(start_address);

    if (!address_in_iat)
    {
        context_->log(scylla_severity::debug, TEXT("searchImportAddressTableInProcess :: addressInIAT not found, startAddress ") PRINTF_DWORD_PTR_FULL, start_address);
        return false;
    }
    return find_iat_start_and_size(address_in_iat, iat_address, iat_size);
}

uintptr_t iat_searcher::find_api_address_in_iat(uintptr_t startAddress)
{
    const size_t MEMORY_READ_SIZE = 200;
    BYTE dataBuffer[MEMORY_READ_SIZE];

    int counter = 0;

    // to detect stolen api
    uintptr_t memory_address = 0;
    size_t memory_size = 0;

    do
    {
        counter++;

        if (!read_remote_memory(startAddress, dataBuffer, sizeof(dataBuffer)))
        {
            context_->log(scylla_severity::debug, TEXT("find_api_address_in_iat :: error reading memory ") PRINTF_DWORD_PTR_FULL, startAddress);
            return 0;
        }

        auto decomposed_data = decompose_memory(startAddress, dataBuffer, sizeof(dataBuffer));
        if (decomposed_data.status == decompose_status::success)
        {
            const DWORD_PTR iatPointer = find_iat_pointer(decomposed_data);
            if (iatPointer)
            {
                if (is_iat_pointer_valid(iatPointer, true, &memory_address, &memory_size))
                {
                    return iatPointer;
                }
            }
        }

        startAddress = find_next_function_address(decomposed_data);
    } while (startAddress != 0 && counter != 8);

    return 0;
}

bool iat_searcher::find_iat_advanced(uintptr_t start_address, uintptr_t* iat_address, size_t* iat_size)
{
    uintptr_t base_address;
    size_t memory_size;

    find_executable_memory_pages_by_start_address(start_address, &base_address, &memory_size);

    if (memory_size == 0)
        return false;

    const auto data_buffer = new BYTE[memory_size];

    if (!read_remote_memory(base_address, data_buffer, memory_size))
    {
        context_->log(scylla_severity::debug, TEXT("findAPIAddressInIAT2 :: error reading memory"));

        delete[] data_buffer;
        return false;
    }

    std::set<uintptr_t> iat_pointers;
    decompose_state decomposer_result;
    BYTE * temp_buffer = data_buffer;
    while ((decomposer_result = decompose_memory(base_address, temp_buffer, memory_size)).status == decompose_status::success)
    {
        find_iat_pointers(decomposer_result, iat_pointers);

        auto next = static_cast<uintptr_t>(decomposer_result.instructions[decomposer_result.instructions.size() - 1].addr - base_address);
        next += decomposer_result.instructions[decomposer_result.instructions.size() - 1].size;
        // Advance ptr and recalc offset.
        temp_buffer += next;

        if (memory_size <= next)
        {
            break;
        }
        memory_size -= next;
        base_address += next;
    }

    if (iat_pointers.empty())
        return false;

    filter_iat_pointers_list(iat_pointers);

    if (iat_pointers.empty())
        return false;

    *iat_address = *(iat_pointers.begin());
    *iat_size = static_cast<DWORD>(*(--iat_pointers.end()) - *(iat_pointers.begin()) + sizeof(DWORD_PTR));

    //some check, more than 2 million addresses?
    if (2000000 * sizeof(DWORD_PTR) < *iat_size)
    {
        *iat_address = 0;
        *iat_size = 0;
        return false;
    }

    context_->log(scylla_severity::debug, TEXT("IAT Search Adv: Found %d (0x%X) possible IAT entries."), iat_pointers.size(), iat_pointers.size());
    context_->log(scylla_severity::debug, TEXT("IAT Search Adv: Possible IAT first ") PRINTF_DWORD_PTR_FULL TEXT(" last ") PRINTF_DWORD_PTR_FULL TEXT(" entry."), *(iat_pointers.begin()), *(--iat_pointers.end()));

    delete[] data_buffer;

    return true;
}

bool iat_searcher::is_iat_pointer_valid(uintptr_t iat_pointer, bool checkRedirects, uintptr_t *memory_address, size_t *memory_size)
{
    uintptr_t api_address = 0;

    if (!read_remote_memory(iat_pointer, &api_address, sizeof(uintptr_t)))
    {
        context_->log(scylla_severity::debug, TEXT("is_iat_pointer_valid :: error reading memory"));
        return false;
    }

    //printf("Win api ? %08X\n",apiAddress);

    if (is_api_address_valid(api_address))
    {
        return true;
    }
    if (checkRedirects)
    {
        //maybe redirected import?
        //if the address is 2 times inside a memory region it is possible a redirected api
        if (api_address > *memory_address && api_address < *memory_address + *memory_size)
        {
            return true;
        }
        get_memory_region_from_address(api_address, memory_address, memory_size);
    }

    return false;
}

uintptr_t iat_searcher::find_iat_pointer(decompose_state &state) const
{
#ifdef DEBUG_COMMENTS
    _DecodedInst inst;
#endif

    for (auto& instruction : state.instructions)
    {
        if (instruction.flags != FLAG_NOT_DECODABLE)
        {
            if (META_GET_FC(instruction.meta) == FC_CALL || META_GET_FC(instruction.meta) == FC_UNC_BRANCH)
            {
                if (instruction.size >= 5)
                {
#ifdef _WIN64
                    if (instruction.flags & FLAG_RIP_RELATIVE)
                    {
#ifdef DEBUG_COMMENTS
                        distorm_format(&state.code_info, &instruction, &inst);
                        context_->log(scylla_severity::debug, TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, instruction.ops[0].type, instruction.size, INSTRUCTION_GET_RIP_TARGET(&instruction));
#endif
                        return INSTRUCTION_GET_RIP_TARGET(&instruction);
                    }
#else
                    if (instruction.ops[0].type == O_DISP)
                    {
                        //jmp dword ptr || call dword ptr
#ifdef DEBUG_COMMENTS
                        distorm_format(&state.code_info, &instruction, &inst);
                        context_->log(scylla_severity::debug, TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, instruction.ops[0].type, instruction.size, instruction.disp);
#endif
                        return static_cast<uintptr_t>(instruction.disp);
                    }
#endif
                }
            }
        }
    }

    return 0;
}

void iat_searcher::find_iat_pointers(decompose_state &state, std::set<uintptr_t>& iat_pointers)
{
#ifdef DEBUG_COMMENTS
    _DecodedInst inst;
#endif

    for (auto &instruction : state.instructions)
    {
        if (instruction.flags != FLAG_NOT_DECODABLE)
        {
            if (META_GET_FC(instruction.meta) == FC_CALL || META_GET_FC(instruction.meta) == FC_UNC_BRANCH)
            {
                if (instruction.size >= 5)
                {
#ifdef _WIN64
                    if (instruction.flags & FLAG_RIP_RELATIVE)
                    {
#ifdef DEBUG_COMMENTS
                        distorm_format(&state.code_info, &instruction, &inst);
                        context_->log(scylla_severity::debug, TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, instruction.ops[0].type, instruction.size, INSTRUCTION_GET_RIP_TARGET(&instruction));
#endif
                        iat_pointers.insert(INSTRUCTION_GET_RIP_TARGET(&instruction));
                    }
#else
                    if (instruction.ops[0].type == O_DISP)
                    {
                        //jmp dword ptr || call dword ptr
#ifdef DEBUG_COMMENTS
                        distorm_format(&state.code_info, &instruction, &inst);
                        context_->log(scylla_severity::debug, TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, instruction.ops[0].type, instruction.size, instruction.disp);
#endif
                        iat_pointers.insert(static_cast<uintptr_t>(instruction.disp));
                    }
#endif
                }
            }
        }
    }
}

void iat_searcher::filter_iat_pointers_list(std::set<uintptr_t>& iat_pointers)
{
    if (iat_pointers.size() <= 2)
    {
        return;
    }

    // to detect stolen api
    uintptr_t memory_address = 0;
    size_t memory_size = 0;

    std::set<uintptr_t>::iterator iter = iat_pointers.begin();
    std::advance(iter, iat_pointers.size() / 2); //start in the middle, important!

    uintptr_t lastPointer = *iter;
    iter++;

    for (; iter != iat_pointers.end(); iter++)
    {
        if ((*iter - lastPointer) > 0x100) //check difference
        {
            if (!is_iat_pointer_valid(lastPointer, false, &memory_address, &memory_size) || !is_iat_pointer_valid(*iter, false, &memory_address, &memory_size))
            {
                iat_pointers.erase(iter, iat_pointers.end());
                break;
            }
            lastPointer = *iter;
        }
        else
        {
            lastPointer = *iter;
        }
    }

    if (iat_pointers.empty()) {
        return;
    }

    //delete bad code pointers.

    bool erased = true;

    while (erased)
    {
        if (iat_pointers.size() <= 1)
            break;

        iter = iat_pointers.begin();
        lastPointer = *iter;
        iter++;

        for (; iter != iat_pointers.end(); iter++)
        {
            if ((*iter - lastPointer) > 0x100) //check pointer difference, a typical difference is 4 on 32bit systems
            {
                const bool isLastValid = is_iat_pointer_valid(lastPointer, false, &memory_address, &memory_size);
                const bool isCurrentValid = is_iat_pointer_valid(*iter, false, &memory_address, &memory_size);
                if (!isLastValid || !isCurrentValid)
                {
                    if (!isLastValid)
                    {
                        iter--;
                    }

                    iat_pointers.erase(iter);
                    erased = true;
                    break;
                }
                erased = false;
                lastPointer = *iter;
            }
            else
            {
                erased = false;
                lastPointer = *iter;
            }
        }
    }
}

bool iat_searcher::find_iat_start_and_size(uintptr_t start_address, uintptr_t* iat_address, size_t* iat_size)
{
    uintptr_t base_address = 0;
    size_t base_size = 0;

    get_memory_base_and_size_for_iat(start_address, &base_address, &base_size);

    if (!base_address)
        return false;
    const size_t buffer_size = base_size * (sizeof(uintptr_t) * 3);
    const auto dataBuffer = new BYTE[buffer_size];

    if (!dataBuffer)
        return false;

    ZeroMemory(dataBuffer, buffer_size);

    if (!read_remote_memory(base_address, dataBuffer, base_size))
    {
        context_->log(scylla_severity::debug, TEXT("find_iat_start_and_size :: error reading memory"));

        delete[] dataBuffer;
        return false;
    }

    *iat_address = find_iat_start_address(base_address, start_address, dataBuffer, buffer_size);

    *iat_size = find_iat_size(base_address, *iat_address, dataBuffer, base_size);

    delete[] dataBuffer;

    return true;
}

uintptr_t iat_searcher::find_iat_start_address(uintptr_t base_address, uintptr_t start_address, LPVOID data_buffer,
    size_t buffer_size) const
{
    auto pIATAddress = reinterpret_cast<DWORD_PTR *>(start_address - base_address + reinterpret_cast<uintptr_t>(data_buffer));

    while (reinterpret_cast<DWORD_PTR>(pIATAddress) != reinterpret_cast<uintptr_t>(data_buffer))
    {
        if (is_invalid_memory_for_iat(*pIATAddress))
        {
            if (reinterpret_cast<DWORD_PTR>(pIATAddress - 1) >= reinterpret_cast<uintptr_t>(data_buffer))
            {
                if (is_invalid_memory_for_iat(*(pIATAddress - 1)))
                {
                    if (reinterpret_cast<DWORD_PTR>(pIATAddress - 2) >= reinterpret_cast<uintptr_t>(data_buffer))
                    {
                        if (!is_api_address_valid(*(pIATAddress - 2)))
                        {
                            return reinterpret_cast<DWORD_PTR>(pIATAddress) - reinterpret_cast<uintptr_t>(data_buffer) + base_address;
                        }
                    }
                }
            }
        }

        pIATAddress--;
    }

    return base_address;
}

size_t iat_searcher::find_iat_size(uintptr_t base_address, uintptr_t iat_address, LPVOID data_buffer,
    size_t buffer_size)
{
    const size_t iatOffset = iat_address - base_address;
    const size_t iatMaxByteSize = buffer_size - iatOffset;
    const auto pIATAddress = reinterpret_cast<DWORD_PTR *>(reinterpret_cast<uint8_t*>(data_buffer) + iatOffset);
    DWORD_PTR CurrentImportAddress;

    context_->log(scylla_severity::debug, TEXT("find_iat_size :: baseAddress %X iatAddress %X dataBuffer %X pIATAddress %X"), base_address, iat_address, data_buffer, pIATAddress);
    for (int iat_index = 0; iat_index * sizeof(DWORD_PTR) < iatMaxByteSize; iat_index++)
    {
        CurrentImportAddress = pIATAddress[iat_index];
        context_->log(scylla_severity::debug, TEXT("find_iat_size :: %p %p %p"), reinterpret_cast<LPCVOID>(&CurrentImportAddress), pIATAddress[iat_index + 1], pIATAddress[iat_index + 1]);

        // Heuristic for end of IAT
        if (is_invalid_memory_for_iat(pIATAddress[iat_index])
            && is_invalid_memory_for_iat(pIATAddress[iat_index + 1])
            && !is_api_address_valid(pIATAddress[iat_index + 2]))
        {
            // IAT usually ends with a null pointer which we need to take into account.
            size_t iatSize = iat_index * sizeof(DWORD_PTR);
            if (!CurrentImportAddress)
                iatSize += sizeof(DWORD_PTR);

            return iatSize;
        }
    }

    // Found no IAT ending in the databuffer => returning everything.
    return buffer_size;
}

uintptr_t iat_searcher::find_next_function_address(decompose_state &state) const
{
#ifdef DEBUG_COMMENTS
    _DecodedInst inst;
#endif

    for (auto& instruction : state.instructions)
    {

        if (instruction.flags != FLAG_NOT_DECODABLE)
        {
            if (META_GET_FC(instruction.meta) == FC_CALL || META_GET_FC(instruction.meta) == FC_UNC_BRANCH)
            {
                if (instruction.size >= 5)
                {
                    if (instruction.ops[0].type == O_PC)
                    {
#ifdef DEBUG_COMMENTS
                        distorm_format(&state.code_info, &instruction, &inst);
                        context_->log(scylla_severity::debug, TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, state.instructions[i].ops[0].type, state.instructions[i].size, INSTRUCTION_GET_TARGET(&state.instructions[i]));
#endif
                        return static_cast<DWORD_PTR>(INSTRUCTION_GET_TARGET(&instruction));
                    }
                }
            }
        }
    }

    return 0;
}

void iat_searcher::find_executable_memory_pages_by_start_address(uintptr_t start_address, uintptr_t* base_address,
    size_t* memory_size)
{
    MEMORY_BASIC_INFORMATION memBasic{};
    DWORD_PTR tempAddress;

    *memory_size = 0;
    *base_address = 0;

    if (VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(start_address), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
    {
        context_->log(scylla_severity::debug, TEXT("find_executable_memory_pages_by_start_address :: VirtualQueryEx error %u"), GetLastError());
        return;
    }

    //search down
    do
    {
        *memory_size = memBasic.RegionSize;
        *base_address = reinterpret_cast<DWORD_PTR>(memBasic.BaseAddress);
        tempAddress = reinterpret_cast<DWORD_PTR>(memBasic.BaseAddress) - 1;

        if (VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(tempAddress), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
        {
            break;
        }
    } while (is_page_executable(memBasic.Protect));

    tempAddress = *base_address;
    memBasic.RegionSize = *memory_size;
    *memory_size = 0;
    //search up
    do
    {
        tempAddress += memBasic.RegionSize;
        *memory_size += memBasic.RegionSize;

        if (VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(tempAddress), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
        {
            break;
        }
    } while (is_page_executable(memBasic.Protect));
}

void adjust_size_for_big_sections(uintptr_t *badValue)
{
    if (*badValue > 100000000)
    {
        *badValue = 100000000;
    }
}

bool is_section_size_too_big(size_t sectionSize) {
    return sectionSize > 100000000;
}

void iat_searcher::get_memory_base_and_size_for_iat(uintptr_t address, uintptr_t* base_address, size_t* base_size) const
{
    MEMORY_BASIC_INFORMATION memBasic1{};
    MEMORY_BASIC_INFORMATION memBasic2{};
    MEMORY_BASIC_INFORMATION memBasic3{};

    *base_address = 0;
    *base_size = 0;

    if (!VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(address), &memBasic2, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        return;
    }

    *base_address = reinterpret_cast<DWORD_PTR>(memBasic2.BaseAddress);
    *base_size = static_cast<DWORD>(memBasic2.RegionSize);

    adjust_size_for_big_sections(base_size);

    //Get the neighbours
    if (VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(reinterpret_cast<DWORD_PTR>(memBasic2.BaseAddress) - 1), &memBasic1, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        if (VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(reinterpret_cast<DWORD_PTR>(memBasic2.BaseAddress) + static_cast<DWORD_PTR>(memBasic2.RegionSize)), &memBasic3, sizeof(MEMORY_BASIC_INFORMATION)))
        {
            if (memBasic3.State != MEM_COMMIT ||
                memBasic1.State != MEM_COMMIT ||
                memBasic3.Protect & PAGE_NOACCESS ||
                memBasic1.Protect & PAGE_NOACCESS)
            {
                return;
            }
            if (is_section_size_too_big(memBasic1.RegionSize) ||
                is_section_size_too_big(memBasic2.RegionSize) ||
                is_section_size_too_big(memBasic3.RegionSize)) {
                return;
            }

            const auto start = reinterpret_cast<DWORD_PTR>(memBasic1.BaseAddress);
            const auto end = reinterpret_cast<DWORD_PTR>(memBasic3.BaseAddress) + static_cast<DWORD_PTR>(memBasic3.RegionSize);

            *base_address = start;
            *base_size = static_cast<DWORD>(end - start);
        }
    }
}
