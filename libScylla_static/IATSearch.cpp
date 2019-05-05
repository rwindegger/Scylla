#include "IATSearch.h"
#include "Scylla.h"
#include "Architecture.h"


bool IATSearch::searchImportAddressTableInProcess( DWORD_PTR startAddress, DWORD_PTR* addressIAT, size_t* sizeIAT, bool advanced )
{
    *addressIAT = 0;
	*sizeIAT = 0;

	if (advanced)
	{
		return findIATAdvanced(startAddress, addressIAT, sizeIAT);
	}

    const DWORD_PTR addressInIAT = findAPIAddressInIAT(startAddress);
	
	if(!addressInIAT)
	{
		Scylla::debugLog.log(TEXT("searchImportAddressTableInProcess :: addressInIAT not found, startAddress ") PRINTF_DWORD_PTR_FULL, startAddress);
		return false;
	}
    return findIATStartAndSize(addressInIAT, addressIAT, sizeIAT);
}

bool IATSearch::findIATAdvanced( DWORD_PTR startAddress, DWORD_PTR* addressIAT, size_t *sizeIAT )
{
    DWORD_PTR baseAddress;
	SIZE_T memorySize;

	findExecutableMemoryPagesByStartAddress(startAddress, &baseAddress, &memorySize);

	if (memorySize == 0)
		return false;

    const auto dataBuffer = new BYTE[memorySize];

	if (!readMemoryFromProcess(static_cast<DWORD_PTR>(baseAddress), memorySize,dataBuffer))
	{
		Scylla::debugLog.log(TEXT("findAPIAddressInIAT2 :: error reading memory"));

		delete [] dataBuffer;
		return false;
	}

	std::set<DWORD_PTR> iatPointers;
    BYTE * tempBuf = dataBuffer;
	while(decomposeMemory(tempBuf, memorySize, static_cast<DWORD_PTR>(baseAddress)) && decomposerInstructionsCount != 0)
	{
		findIATPointers(iatPointers);

	    auto next = static_cast<DWORD_PTR>(decomposerResult[decomposerInstructionsCount - 1].addr - baseAddress);
		next += decomposerResult[decomposerInstructionsCount - 1].size;
		// Advance ptr and recalc offset.
		tempBuf += next;

		if (memorySize <= next)
		{
			break;
		}
		memorySize -= next;
		baseAddress += next;
	}

	if (iatPointers.empty())
		return false;

	filterIATPointersList(iatPointers);

	if (iatPointers.empty())
		return false;

	*addressIAT = *(iatPointers.begin());
	*sizeIAT = static_cast<DWORD>(*(--iatPointers.end()) - *(iatPointers.begin()) + sizeof(DWORD_PTR));

	//some check, more than 2 million addresses?
	if (2000000 * sizeof(DWORD_PTR) < *sizeIAT)
	{
		*addressIAT = 0;
		*sizeIAT = 0;
		return false;
	}

	Scylla::Log->log(TEXT("IAT Search Adv: Found %d (0x%X) possible IAT entries."), iatPointers.size(), iatPointers.size());
	Scylla::Log->log(TEXT("IAT Search Adv: Possible IAT first ") PRINTF_DWORD_PTR_FULL TEXT(" last ") PRINTF_DWORD_PTR_FULL TEXT(" entry."), *(iatPointers.begin()), *(--iatPointers.end()));

	delete [] dataBuffer;

	return true;
}

DWORD_PTR IATSearch::findAPIAddressInIAT(DWORD_PTR startAddress)
{
	const size_t MEMORY_READ_SIZE = 200;
	BYTE dataBuffer[MEMORY_READ_SIZE];

    int counter = 0;

	// to detect stolen api
	memoryAddress = 0;
	memorySize = 0;

	do 
	{
		counter++;

		if (!readMemoryFromProcess(startAddress, sizeof dataBuffer, dataBuffer))
		{
			Scylla::debugLog.log(TEXT("findAPIAddressInIAT :: error reading memory ") PRINTF_DWORD_PTR_FULL, startAddress);
			return 0;
		}

		if (decomposeMemory(dataBuffer, sizeof dataBuffer, startAddress))
		{
		    const DWORD_PTR iatPointer = findIATPointer();
			if (iatPointer)
			{
				if (isIATPointerValid(iatPointer, true))
				{
					return iatPointer;
				}
			}
		}

		startAddress = findNextFunctionAddress();
		//printf("startAddress %08X\n",startAddress);
	} while (startAddress != 0 && counter != 8);

	return 0;
}

DWORD_PTR IATSearch::findNextFunctionAddress()
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	for (unsigned int i = 0; i < decomposerInstructionsCount; i++)
	{

		if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
		{
			if (META_GET_FC(decomposerResult[i].meta) == FC_CALL || META_GET_FC(decomposerResult[i].meta) == FC_UNC_BRANCH)
			{
				if (decomposerResult[i].size >= 5)
				{
					if (decomposerResult[i].ops[0].type == O_PC)
					{
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Scylla::debugLog.log(TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, INSTRUCTION_GET_TARGET(&decomposerResult[i]));
#endif
						return static_cast<DWORD_PTR>(INSTRUCTION_GET_TARGET(&decomposerResult[i]));
					}
				}
			}
		}
	}

	return 0;
}

DWORD_PTR IATSearch::findIATPointer()
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	for (unsigned int i = 0; i < decomposerInstructionsCount; i++)
	{
		if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
		{
			if (META_GET_FC(decomposerResult[i].meta) == FC_CALL || META_GET_FC(decomposerResult[i].meta) == FC_UNC_BRANCH)
			{
				if (decomposerResult[i].size >= 5)
				{
#ifdef _WIN64
					if (decomposerResult[i].flags & FLAG_RIP_RELATIVE)
					{
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Scylla::debugLog.log(TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, INSTRUCTION_GET_RIP_TARGET(&decomposerResult[i]));
#endif
						return INSTRUCTION_GET_RIP_TARGET(&decomposerResult[i]);
					}
#else
					if (decomposerResult[i].ops[0].type == O_DISP)
					{
						//jmp dword ptr || call dword ptr
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Scylla::debugLog.log(TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, decomposerResult[i].disp);
#endif
						return (DWORD_PTR)decomposerResult[i].disp;
					}
#endif
				}
			}
		}
	}

	return 0;
}

bool IATSearch::isIATPointerValid(DWORD_PTR iatPointer, bool checkRedirects)
{
	DWORD_PTR apiAddress = 0;

	if (!readMemoryFromProcess(iatPointer,sizeof(DWORD_PTR),&apiAddress))
	{
		Scylla::debugLog.log(TEXT("isIATPointerValid :: error reading memory"));
		return false;
	}

	//printf("Win api ? %08X\n",apiAddress);

	if (isApiAddressValid(apiAddress) != 0)
	{
		return true;
	}
    if (checkRedirects)
    {
        //maybe redirected import?
        //if the address is 2 times inside a memory region it is possible a redirected api
        if (apiAddress > memoryAddress && apiAddress < memoryAddress+memorySize)
        {
            return true;
        }
        getMemoryRegionFromAddress(apiAddress, &memoryAddress, &memorySize);
    }

    return false;
}

bool IATSearch::findIATStartAndSize(DWORD_PTR address, DWORD_PTR * addressIAT, size_t *sizeIAT) const
{
    DWORD_PTR baseAddress = 0;
    DWORD baseSize = 0;

    getMemoryBaseAndSizeForIat(address, &baseAddress, &baseSize);

    if (!baseAddress)
        return false;

    const auto dataBuffer = new BYTE[baseSize * (sizeof(DWORD_PTR)*3)];

    if (!dataBuffer)
        return false;

	ZeroMemory(dataBuffer, baseSize * (sizeof(DWORD_PTR)*3));

	if (!readMemoryFromProcess(baseAddress, baseSize, dataBuffer))
	{
		Scylla::debugLog.log(TEXT("findIATStartAddress :: error reading memory"));

		delete [] dataBuffer;
		return false;
	}

	//printf("address %X memBasic.BaseAddress %X memBasic.RegionSize %X\n",address,memBasic.BaseAddress,memBasic.RegionSize);

	*addressIAT = findIATStartAddress(baseAddress, address, dataBuffer);

	*sizeIAT = findIATSize(baseAddress, *addressIAT, dataBuffer, baseSize);

	delete [] dataBuffer;

	return true;
}

DWORD_PTR IATSearch::findIATStartAddress(DWORD_PTR baseAddress, DWORD_PTR startAddress, BYTE * dataBuffer) const
{
    auto pIATAddress = reinterpret_cast<DWORD_PTR *>(startAddress - baseAddress + reinterpret_cast<DWORD_PTR>(dataBuffer));

	while(reinterpret_cast<DWORD_PTR>(pIATAddress) != reinterpret_cast<DWORD_PTR>(dataBuffer))
	{
		if (isInvalidMemoryForIat(*pIATAddress))
		{
            if (reinterpret_cast<DWORD_PTR>(pIATAddress - 1) >= reinterpret_cast<DWORD_PTR>(dataBuffer))
            {
                if (isInvalidMemoryForIat(*(pIATAddress - 1)))
                {
                    if (reinterpret_cast<DWORD_PTR>(pIATAddress - 2) >= reinterpret_cast<DWORD_PTR>(dataBuffer))
                    {
                        if (!isApiAddressValid(*(pIATAddress - 2)))
                        {
                            return reinterpret_cast<DWORD_PTR>(pIATAddress) - reinterpret_cast<DWORD_PTR>(dataBuffer) + baseAddress;
                        }
                    }
                }
            }
		}

		pIATAddress--;
	}

	return baseAddress;
}

size_t IATSearch::findIATSize(DWORD_PTR baseAddress, DWORD_PTR iatAddress, BYTE * dataBuffer, size_t bufferSize) const
{
    const size_t iatOffset = iatAddress - baseAddress;
    const size_t iatMaxByteSize = bufferSize - iatOffset;
    const auto pIATAddress = reinterpret_cast<DWORD_PTR *>(dataBuffer + iatOffset);
	DWORD_PTR CurrentImportAddress;

	Scylla::debugLog.log(TEXT("findIATSize :: baseAddress %X iatAddress %X dataBuffer %X pIATAddress %X"), baseAddress, iatAddress, dataBuffer, pIATAddress);
	for (int iat_index = 0; iat_index * sizeof(DWORD_PTR) < iatMaxByteSize; iat_index++)
	{
		CurrentImportAddress = pIATAddress[iat_index];
		Scylla::debugLog.log(TEXT("findIATSize :: %p %p %p"), reinterpret_cast<LPCVOID>(&CurrentImportAddress), pIATAddress[iat_index + 1], pIATAddress[iat_index + 1]);
		
		// Heuristic for end of IAT
		if (isInvalidMemoryForIat(pIATAddress[iat_index])
			&& isInvalidMemoryForIat(pIATAddress[iat_index + 1])
			&& !isApiAddressValid(pIATAddress[iat_index + 2]))
		{
			// IAT usually ends with a null pointer which we need to take into account.
			size_t iatSize = iat_index * sizeof(DWORD_PTR);
			if (!CurrentImportAddress)
				iatSize += sizeof(DWORD_PTR);

			return iatSize;
		}

	}

	// Found no IAT ending in the databuffer => returning everything.
	return bufferSize;
}

void IATSearch::findIATPointers(std::set<DWORD_PTR> & iatPointers)
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	for (unsigned int i = 0; i < decomposerInstructionsCount; i++)
	{
		if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
		{
			if (META_GET_FC(decomposerResult[i].meta) == FC_CALL || META_GET_FC(decomposerResult[i].meta) == FC_UNC_BRANCH)
			{
				if (decomposerResult[i].size >= 5)
				{
#ifdef _WIN64
					if (decomposerResult[i].flags & FLAG_RIP_RELATIVE)
					{
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Scylla::debugLog.log(TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, INSTRUCTION_GET_RIP_TARGET(&decomposerResult[i]));
#endif
						iatPointers.insert(INSTRUCTION_GET_RIP_TARGET(&decomposerResult[i]));
					}
#else
					if (decomposerResult[i].ops[0].type == O_DISP)
					{
						//jmp dword ptr || call dword ptr
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Scylla::debugLog.log(TEXT("%S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, decomposerResult[i].disp);
#endif
						iatPointers.insert((DWORD_PTR)decomposerResult[i].disp);
					}
#endif
				}
			}
		}
	}


}

void IATSearch::findExecutableMemoryPagesByStartAddress( DWORD_PTR startAddress, DWORD_PTR* baseAddress, SIZE_T* memorySize )
{
    MEMORY_BASIC_INFORMATION memBasic{};
	DWORD_PTR tempAddress;

	*memorySize = 0;
	*baseAddress = 0;

	if (VirtualQueryEx(hProcess,reinterpret_cast<LPCVOID>(startAddress), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
	{
		Scylla::debugLog.log(TEXT("findIATStartAddress :: VirtualQueryEx error %u"), GetLastError());
		return;
	}

	//search down
	do
	{
		*memorySize = memBasic.RegionSize;
		*baseAddress = reinterpret_cast<DWORD_PTR>(memBasic.BaseAddress);
		tempAddress = reinterpret_cast<DWORD_PTR>(memBasic.BaseAddress) - 1;

		if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(tempAddress), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
		{
			break;
		}
	} while (isPageExecutable(memBasic.Protect));

	tempAddress = *baseAddress;
	memBasic.RegionSize = *memorySize;
	*memorySize = 0;
	//search up
	do
	{
		tempAddress += memBasic.RegionSize;
		*memorySize += memBasic.RegionSize;

		if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(tempAddress), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
		{
			break;
		}
	} while (isPageExecutable(memBasic.Protect));
}

void IATSearch::filterIATPointersList( std::set<DWORD_PTR> & iatPointers )
{
    if (iatPointers.size() <= 2)
	{
		return;
	}

	std::set<DWORD_PTR>::iterator iter = iatPointers.begin();
	std::advance(iter, iatPointers.size() / 2); //start in the middle, important!

	DWORD_PTR lastPointer = *iter;
	iter++;

	for (; iter != iatPointers.end(); iter++)
	{
		if ((*iter - lastPointer) > 0x100) //check difference
		{
            if (!isIATPointerValid(lastPointer, false) || !isIATPointerValid(*iter, false))
            {
                iatPointers.erase(iter, iatPointers.end());
                break;
            }
		    lastPointer = *iter;
		}
		else
		{
			lastPointer = *iter;
		}
	}

	if (iatPointers.empty()) {
		return;
	}

	//delete bad code pointers.

	bool erased = true;

	while(erased)
	{
		if (iatPointers.size() <= 1)
			break;

		iter = iatPointers.begin();
		lastPointer = *iter;
		iter++;

		for (; iter != iatPointers.end(); iter++)
		{
			if ((*iter - lastPointer) > 0x100) //check pointer difference, a typical difference is 4 on 32bit systems
			{
			    const bool isLastValid = isIATPointerValid(lastPointer, false);
			    const bool isCurrentValid = isIATPointerValid(*iter, false);
                if (!isLastValid || !isCurrentValid)
                {
					if (!isLastValid)
					{
						iter--;
					}
                    
                    iatPointers.erase(iter);
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

//A big section size is a common anti-debug/anti-dump trick, limit the max size to 100 000 000 bytes

void adjustSizeForBigSections(DWORD * badValue)
{
	if (*badValue > 100000000)
	{
		*badValue = 100000000;
	}
}

bool isSectionSizeTooBig(SIZE_T sectionSize) {
	return sectionSize > 100000000;
}

void IATSearch::getMemoryBaseAndSizeForIat( DWORD_PTR address, DWORD_PTR* baseAddress, DWORD* baseSize )
{
    MEMORY_BASIC_INFORMATION memBasic1{};
    MEMORY_BASIC_INFORMATION memBasic2{};
    MEMORY_BASIC_INFORMATION memBasic3{};

    *baseAddress = 0;
    *baseSize = 0;

    if (!VirtualQueryEx(hProcess,reinterpret_cast<LPCVOID>(address), &memBasic2, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        return;
    }

    *baseAddress = reinterpret_cast<DWORD_PTR>(memBasic2.BaseAddress);
    *baseSize = static_cast<DWORD>(memBasic2.RegionSize);

	adjustSizeForBigSections(baseSize);

    //Get the neighbours
    if (VirtualQueryEx(hProcess,reinterpret_cast<LPCVOID>(reinterpret_cast<DWORD_PTR>(memBasic2.BaseAddress) - 1), &memBasic1, sizeof(MEMORY_BASIC_INFORMATION)))
    {
		if (VirtualQueryEx(hProcess,reinterpret_cast<LPCVOID>(reinterpret_cast<DWORD_PTR>(memBasic2.BaseAddress) + static_cast<DWORD_PTR>(memBasic2.RegionSize)), &memBasic3, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			if (memBasic3.State != MEM_COMMIT || 
				memBasic1.State != MEM_COMMIT || 
				memBasic3.Protect & PAGE_NOACCESS || 
				memBasic1.Protect & PAGE_NOACCESS)
			{
				return;
			}
		    if (isSectionSizeTooBig(memBasic1.RegionSize) || 
		        isSectionSizeTooBig(memBasic2.RegionSize) || 
		        isSectionSizeTooBig(memBasic3.RegionSize)) {
		        return;
		    }

		    const auto start = reinterpret_cast<DWORD_PTR>(memBasic1.BaseAddress);
		    const auto end = reinterpret_cast<DWORD_PTR>(memBasic3.BaseAddress) + static_cast<DWORD_PTR>(memBasic3.RegionSize);

		    *baseAddress = start;
		    *baseSize = static_cast<DWORD>(end - start);
		}
    }
}
