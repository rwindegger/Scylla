#include "IATReferenceScan.h"
#include "Scylla.h"
#include "Architecture.h"
#include <set>

FileLog IATReferenceScan::directImportLog(TEXT("Scylla_direct_imports.log"));

int IATReferenceScan::numberOfFoundDirectImports()
{
	return static_cast<int>(iatDirectImportList.size());
}

int IATReferenceScan::numberOfFoundUniqueDirectImports()
{
	std::set<DWORD_PTR> apiPointers;
	for (auto& iter : iatDirectImportList)
	{
		IATReference * ref = &iter;
		apiPointers.insert(ref->targetAddressInIat);
	}

	return static_cast<int>(apiPointers.size());
}

int IATReferenceScan::numberOfDirectImportApisNotInIat()
{
	std::set<DWORD_PTR> apiPointers;
	for (auto& iter : iatDirectImportList)
	{
		IATReference * ref = &iter;

		if (ref->targetPointer == 0)
		{
			apiPointers.insert(ref->targetAddressInIat);
		}
	}

	return static_cast<int>(apiPointers.size());
}

int IATReferenceScan::getSizeInBytesOfJumpTableInSection()
{
	return numberOfFoundUniqueDirectImports() * 6; //for x86 and x64 the same size, FF25 00000000
}

void IATReferenceScan::startScan(DWORD_PTR imageBase, DWORD imageSize, DWORD_PTR iatAddress, DWORD iatSize)
{
	MEMORY_BASIC_INFORMATION memBasic{};

	IatAddressVA = iatAddress;
	IatSize = iatSize;
	ImageBase = imageBase;
	ImageSize = imageSize;

	if (ScanForNormalImports)
	{
		iatReferenceList.clear();
		iatReferenceList.reserve(200);
	}
	if (ScanForDirectImports)
	{
		iatDirectImportList.clear();
		iatDirectImportList.reserve(50);
	}

	DWORD_PTR section = imageBase;

	do
	{
		if (!VirtualQueryEx(ProcessAccessHelp::hProcess, reinterpret_cast<LPCVOID>(section), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			Scylla::debugLog.log(TEXT("VirtualQueryEx failed %d"), GetLastError());


			break;
		}
		else
		{
			if (ProcessAccessHelp::isPageExecutable(memBasic.Protect))
			{
				//do read and scan
				scanMemoryPage(memBasic.BaseAddress, memBasic.RegionSize);
			}
		}

		section = static_cast<DWORD_PTR>(static_cast<SIZE_T>(section) + memBasic.RegionSize);

	} while (section < imageBase + imageSize);


}

//void IATReferenceScan::patchNewIatBaseMemory(DWORD_PTR newIatBaseAddress)
//{
//	NewIatAddressVA = newIatBaseAddress;
//
//	for (std::vector<IATReference>::iterator iter = iatReferenceList.begin(); iter != iatReferenceList.end(); iter++)
//	{
//		patchReferenceInMemory(&(*iter));
//	}
//}
//
//void IATReferenceScan::patchNewIatBaseFile(DWORD_PTR newIatBaseAddress)
//{
//	NewIatAddressVA = newIatBaseAddress;
//
//	for (std::vector<IATReference>::iterator iter = iatReferenceList.begin(); iter != iatReferenceList.end(); iter++)
//	{
//		patchReferenceInFile(&(*iter));
//	}
//}

void IATReferenceScan::patchDirectImportsMemory( bool junkByteAfterInstruction )
{
	JunkByteAfterInstruction = junkByteAfterInstruction;
	for (auto& iter : iatDirectImportList)
	{
		patchDirectImportInMemory(&iter);
	}
}

void IATReferenceScan::scanMemoryPage( PVOID BaseAddress, SIZE_T RegionSize )
{
    const auto dataBuffer = reinterpret_cast<BYTE *>(calloc(RegionSize, 1));
	BYTE * currentPos = dataBuffer;
    auto currentSize = static_cast<int>(RegionSize);
    auto currentOffset = reinterpret_cast<DWORD_PTR>(BaseAddress);
    unsigned int instructionsCount=0;

	if (!dataBuffer)
		return;

	if (ProcessAccessHelp::readMemoryFromProcess(reinterpret_cast<DWORD_PTR>(BaseAddress), RegionSize, static_cast<LPVOID>(dataBuffer)))
	{
		while (true)
		{
			ZeroMemory(&ProcessAccessHelp::decomposerCi, sizeof(_CodeInfo));
			ProcessAccessHelp::decomposerCi.code = currentPos;
			ProcessAccessHelp::decomposerCi.codeLen = currentSize;
			ProcessAccessHelp::decomposerCi.dt = ProcessAccessHelp::dt;
			ProcessAccessHelp::decomposerCi.codeOffset = currentOffset;

			instructionsCount = 0;

		    const _DecodeResult res = distorm_decompose(&ProcessAccessHelp::decomposerCi, ProcessAccessHelp::decomposerResult, sizeof ProcessAccessHelp::decomposerResult/sizeof ProcessAccessHelp::decomposerResult[0], &instructionsCount);

			if (res == DECRES_INPUTERR)
			{
				break;
			}

			for (unsigned int i = 0; i < instructionsCount; i++) 
			{
				if (ProcessAccessHelp::decomposerResult[i].flags != FLAG_NOT_DECODABLE)
				{
					analyzeInstruction(&ProcessAccessHelp::decomposerResult[i]);
				}
			}

			if (res == DECRES_SUCCESS) break; // All instructions were decoded.
			else if (instructionsCount == 0) break;

			unsigned int next = static_cast<unsigned long>(ProcessAccessHelp::decomposerResult[instructionsCount - 1].addr - ProcessAccessHelp::
			    decomposerResult[0].addr);

			if (ProcessAccessHelp::decomposerResult[instructionsCount-1].flags != FLAG_NOT_DECODABLE)
			{
				next += ProcessAccessHelp::decomposerResult[instructionsCount-1].size;
			}

			currentPos += next;
			currentOffset += next;
			currentSize -= next;
		}
	}

	free(dataBuffer);
}

void IATReferenceScan::analyzeInstruction( _DInst * instruction )
{
	if (ScanForNormalImports)
	{
		findNormalIatReference(instruction);
	}
	
	if (ScanForDirectImports)
	{
		findDirectIatReferenceMov(instruction);
		
#ifndef _WIN64
		findDirectIatReferenceCallJmp(instruction);
		findDirectIatReferenceLea(instruction);
		findDirectIatReferencePush(instruction);
#endif
	}
}

void IATReferenceScan::findNormalIatReference( _DInst * instruction )
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	IATReference ref{};


	if (META_GET_FC(instruction->meta) == FC_CALL || META_GET_FC(instruction->meta) == FC_UNC_BRANCH)
	{
		if (instruction->size >= 5)
		{
			if (META_GET_FC(instruction->meta) == FC_CALL)
			{
				ref.type = IAT_REFERENCE_PTR_CALL;
			}
			else
			{
				ref.type = IAT_REFERENCE_PTR_JMP;
			}
			ref.addressVA = static_cast<DWORD_PTR>(instruction->addr);
			ref.instructionSize = instruction->size;

#ifdef _WIN64
			if (instruction->flags & FLAG_RIP_RELATIVE)
			{

#ifdef DEBUG_COMMENTS
				distorm_format(&ProcessAccessHelp::decomposerCi, instruction, &inst);
				Scylla::debugLog.log(PRINTF_DWORD_PTR_FULL TEXT(" ") PRINTF_DWORD_PTR_FULL TEXT(" %S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, (DWORD_PTR)instruction->addr, ImageBase, inst.mnemonic.p, inst.operands.p, instruction->ops[0].type, instruction->size, INSTRUCTION_GET_RIP_TARGET(instruction));
#endif

				if (INSTRUCTION_GET_RIP_TARGET(instruction) >= IatAddressVA && INSTRUCTION_GET_RIP_TARGET(instruction) < IatAddressVA + IatSize)
				{
					ref.targetPointer = INSTRUCTION_GET_RIP_TARGET(instruction);

					getIatEntryAddress(&ref);

					//Scylla::debugLog.log(L"iat entry "PRINTF_DWORD_PTR_FULL,ref.targetAddressInIat);

					iatReferenceList.push_back(ref);
				}
			}
#else

			if (instruction->ops[0].type == O_DISP)
			{
				//jmp dword ptr || call dword ptr
#ifdef DEBUG_COMMENTS
				distorm_format(&ProcessAccessHelp::decomposerCi, instruction, &inst);
				Scylla::debugLog.log(PRINTF_DWORD_PTR_FULL TEXT(" ") PRINTF_DWORD_PTR_FULL TEXT(" %S %S %d %d - target address: ") PRINTF_DWORD_PTR_FULL, (DWORD_PTR)instruction->addr, ImageBase, inst.mnemonic.p, inst.operands.p, instruction->ops[0].type, instruction->size, instruction->disp);
#endif
				
				if (instruction->disp >= IatAddressVA && instruction->disp < (IatAddressVA + IatSize))
				{
					ref.targetPointer = (DWORD_PTR)instruction->disp;
					
					getIatEntryAddress(&ref);

					//Scylla::debugLog.log(L"iat entry "PRINTF_DWORD_PTR_FULL,ref.targetAddressInIat);

					iatReferenceList.push_back(ref);
				}
			}
#endif
		}
	}
}

void IATReferenceScan::getIatEntryAddress( IATReference * ref )
{
	if (!ProcessAccessHelp::readMemoryFromProcess(ref->targetPointer, sizeof(DWORD_PTR), &ref->targetAddressInIat))
	{
		ref->targetAddressInIat = 0;
	}
}

bool IATReferenceScan::isAddressValidImageMemory( DWORD_PTR address )
{
	MEMORY_BASIC_INFORMATION memBasic{};

	if (!VirtualQueryEx(ProcessAccessHelp::hProcess, reinterpret_cast<LPCVOID>(address), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		return false;
	}

	return memBasic.Type == MEM_IMAGE && ProcessAccessHelp::isPageExecutable(memBasic.Protect);
}

void IATReferenceScan::patchReferenceInMemory( IATReference * ref ) const
{
    const DWORD_PTR newIatAddressPointer = ref->targetPointer - IatAddressVA + NewIatAddressRVA;

	DWORD patchBytes;

#ifdef _WIN64
	patchBytes = static_cast<DWORD>(newIatAddressPointer - ref->addressVA - 6);
#else
	patchBytes = newIatAddressPointer;
#endif
	ProcessAccessHelp::writeMemoryToProcess(ref->addressVA + 2, sizeof(DWORD), &patchBytes);
}

void IATReferenceScan::patchDirectImportInMemory( IATReference * ref ) const
{
	DWORD patchBytes;
	BYTE patchPreBytes[2];

	if (ref->targetPointer)
	{
		patchPreBytes[0] = 0xFF;

		if (ref->type == IAT_REFERENCE_DIRECT_CALL) //FF15
		{
			patchPreBytes[1] = 0x15;
		}
		else if (ref->type == IAT_REFERENCE_DIRECT_JMP) //FF25
		{
			patchPreBytes[1] = 0x25;
		}
		else
		{
			return;
		}

		if (!JunkByteAfterInstruction)
		{
			ref->addressVA -= 1;
		}

		ProcessAccessHelp::writeMemoryToProcess(ref->addressVA, 2, patchPreBytes);

#ifdef _WIN64
		patchBytes = static_cast<DWORD>(ref->targetPointer - ref->addressVA - 6);
#else
		patchBytes = ref->targetPointer;
#endif
		ProcessAccessHelp::writeMemoryToProcess(ref->addressVA + 2, sizeof(DWORD), &patchBytes);
	}
}

DWORD_PTR IATReferenceScan::lookUpIatForPointer( DWORD_PTR addr )
{
	if (!iatBackup)
	{
		iatBackup = reinterpret_cast<DWORD_PTR *>(calloc(IatSize + sizeof(DWORD_PTR), 1));
		if (!iatBackup)
		{
			return 0;
		}
		if (!ProcessAccessHelp::readMemoryFromProcess(IatAddressVA, IatSize, iatBackup))
		{
			free(iatBackup);
			iatBackup = nullptr;
			return 0;
		}
	}

	for (int i = 0; i < static_cast<int>(IatSize) / static_cast<int>(sizeof(DWORD_PTR));i++)
	{
		if (iatBackup[i] == addr)
		{
			return reinterpret_cast<DWORD_PTR>(&iatBackup[i]) - reinterpret_cast<DWORD_PTR>(iatBackup) + IatAddressVA;
		}
	}

	return 0;
}

void IATReferenceScan::patchNewIat(DWORD_PTR stdImagebase, DWORD_PTR newIatBaseAddress, PeParser * peParser)
{
	NewIatAddressRVA = newIatBaseAddress;
	DWORD patchBytes;

	for (auto& iter : iatReferenceList)
	{
		IATReference * ref = &iter;

	    const DWORD_PTR newIatAddressPointer = ref->targetPointer - IatAddressVA + NewIatAddressRVA + stdImagebase;

#ifdef _WIN64
		patchBytes = static_cast<DWORD>(newIatAddressPointer - (ref->addressVA - ImageBase + stdImagebase) - 6);
#else
		patchBytes = newIatAddressPointer;
#endif
	    const DWORD_PTR patchOffset = peParser->convertRVAToOffsetRelative(ref->addressVA - ImageBase);
		const int index = peParser->convertRVAToOffsetVectorIndex(ref->addressVA - ImageBase);
		BYTE * memory = peParser->getSectionMemoryByIndex(index);
		const DWORD memorySize = peParser->getSectionMemorySizeByIndex(index);


		if (memorySize < static_cast<DWORD>(patchOffset + 6))
		{
			Scylla::debugLog.log(TEXT("Error - Cannot fix IAT reference RVA: ") PRINTF_DWORD_PTR_FULL, ref->addressVA - ImageBase);
		}
		else
		{
			memory += patchOffset + 2;		

			*reinterpret_cast<DWORD *>(memory) = patchBytes;
		}
		//Scylla::debugLog.log(L"address %X old %X new %X",ref->addressVA, ref->targetPointer, newIatAddressPointer);

	}
}

void IATReferenceScan::printDirectImportLog()
{
	IATReferenceScan::directImportLog.log(TEXT("------------------------------------------------------------"));
	IATReferenceScan::directImportLog.log(TEXT("ImageBase ") PRINTF_DWORD_PTR_FULL TEXT(" ImageSize %08X IATAddress ") PRINTF_DWORD_PTR_FULL TEXT(" IATSize 0x%X"), ImageBase, ImageSize, IatAddressVA, IatSize);
	int count = 0;
	bool isSuspect = false;

	for (auto& iter : iatDirectImportList)
	{
		IATReference * ref = &iter;
		
		ApiInfo * apiInfo = apiReader->getApiByVirtualAddress(ref->targetAddressInIat, &isSuspect);

		count++;
		LPCTSTR type = TEXT("U");

		if (ref->type == IAT_REFERENCE_DIRECT_CALL)
		{
			type = TEXT("CALL");
		}
		else if (ref->type == IAT_REFERENCE_DIRECT_JMP)
		{
			type = TEXT("JMP");
		}
		else if (ref->type == IAT_REFERENCE_DIRECT_MOV)
		{
			type = TEXT("MOV");
		}
		else if (ref->type == IAT_REFERENCE_DIRECT_PUSH)
		{
			type = TEXT("PUSH");
		}
		else if (ref->type == IAT_REFERENCE_DIRECT_LEA)
		{
			type = TEXT("LEA");
		}

		IATReferenceScan::directImportLog.log(TEXT("%04d AddrVA ") PRINTF_DWORD_PTR_FULL TEXT(" Type %s Value ") PRINTF_DWORD_PTR_FULL TEXT(" IatRefPointer ") PRINTF_DWORD_PTR_FULL TEXT(" Api %s %S"), count, ref->addressVA, type, ref->targetAddressInIat, ref->targetPointer,apiInfo->module->getFilename(), apiInfo->name);

	}

	IATReferenceScan::directImportLog.log(TEXT("------------------------------------------------------------"));
}

void IATReferenceScan::findDirectIatReferenceCallJmp( _DInst * instruction )
{
	IATReference ref{};

	if (META_GET_FC(instruction->meta) == FC_CALL || META_GET_FC(instruction->meta) == FC_UNC_BRANCH)
	{
		if (instruction->size >= 5 && instruction->ops[0].type == O_PC) //CALL/JMP 0x00000000
		{
			if (META_GET_FC(instruction->meta) == FC_CALL)
			{
				ref.type = IAT_REFERENCE_DIRECT_CALL;
			}
			else
			{
				ref.type = IAT_REFERENCE_DIRECT_JMP;
			}
			
			ref.targetAddressInIat = static_cast<DWORD_PTR>(INSTRUCTION_GET_TARGET(instruction));

			checkMemoryRangeAndAddToList(&ref, instruction);
		}
	}
}

void IATReferenceScan::findDirectIatReferenceMov( _DInst * instruction )
{
	IATReference ref{};
	ref.type = IAT_REFERENCE_DIRECT_MOV;

	if (instruction->opcode == I_MOV)
	{
#ifdef _WIN64
		if (instruction->size >= 7) //MOV REGISTER, 0xFFFFFFFFFFFFFFFF
#else
		if (instruction->size >= 5) //MOV REGISTER, 0xFFFFFFFF
#endif
		{
			if (instruction->ops[0].type == O_REG && instruction->ops[1].type == O_IMM)
			{
				ref.targetAddressInIat = static_cast<DWORD_PTR>(instruction->imm.qword);

				checkMemoryRangeAndAddToList(&ref, instruction);
			}
		}
	}
}

void IATReferenceScan::findDirectIatReferencePush( _DInst * instruction )
{
	IATReference ref{};
	ref.type = IAT_REFERENCE_DIRECT_PUSH;

	if (instruction->size >= 5 && instruction->opcode == I_PUSH)
	{
		ref.targetAddressInIat = static_cast<DWORD_PTR>(instruction->imm.qword);

		checkMemoryRangeAndAddToList(&ref, instruction);
	}
}

void IATReferenceScan::findDirectIatReferenceLea( _DInst * instruction )
{
	IATReference ref{};
	ref.type = IAT_REFERENCE_DIRECT_LEA;

	if (instruction->size >= 5 && instruction->opcode == I_LEA)
	{
		if (instruction->ops[0].type == O_REG && instruction->ops[1].type == O_DISP) //LEA EDX, [0xb58bb8]
		{
			ref.targetAddressInIat = static_cast<DWORD_PTR>(instruction->disp);

			checkMemoryRangeAndAddToList(&ref, instruction);
		}
	}
}

void IATReferenceScan::checkMemoryRangeAndAddToList( IATReference * ref, _DInst * instruction )
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	if (ref->targetAddressInIat > 0x000FFFFF && ref->targetAddressInIat != static_cast<DWORD_PTR>(-1))
	{
		if (ref->targetAddressInIat < ImageBase || ref->targetAddressInIat > ImageBase+ImageSize) //outside pe image
		{
			//if (isAddressValidImageMemory(ref->targetAddressInIat))
			{
				bool isSuspect = false;
				if (apiReader->getApiByVirtualAddress(ref->targetAddressInIat, &isSuspect) != nullptr)
				{
					ref->addressVA = static_cast<DWORD_PTR>(instruction->addr);
					ref->instructionSize = instruction->size;
					ref->targetPointer = lookUpIatForPointer(ref->targetAddressInIat);

#ifdef DEBUG_COMMENTS
					distorm_format(&ProcessAccessHelp::decomposerCi, instruction, &inst);
					Scylla::debugLog.log(PRINTF_DWORD_PTR_FULL L" " PRINTF_DWORD_PTR_FULL L" %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL,(DWORD_PTR)instruction->addr, ImageBase, inst.mnemonic.p, inst.operands.p, instruction->ops[0].type, instruction->size, ref->targetAddressInIat);
#endif
					iatDirectImportList.push_back(*ref);
				}
			}
		}
	}
}

void IATReferenceScan::patchDirectJumpTableEntry(DWORD_PTR targetIatPointer, DWORD_PTR stdImagebase, DWORD directImportsJumpTableRVA, PeParser * peParser, BYTE * jmpTableMemory, DWORD newIatBase )
{
    DWORD patchBytes;
	for (auto& iter : iatDirectImportList)
	{
		IATReference * ref = &iter;

		//only one jmp in table for different direct imports with same iat address
		if (ref->targetPointer == targetIatPointer)
		{
			//patch dump
		    const auto patchOffset = static_cast<DWORD>(peParser->convertRVAToOffsetRelative(ref->addressVA - ImageBase));
			const int index = peParser->convertRVAToOffsetVectorIndex(ref->addressVA - ImageBase);
			BYTE * memory = peParser->getSectionMemoryByIndex(index);
			const DWORD memorySize = peParser->getSectionMemorySizeByIndex(index);
			const DWORD sectionRVA = peParser->getSectionAddressRVAByIndex(index);

			if (ref->type == IAT_REFERENCE_DIRECT_CALL || ref->type == IAT_REFERENCE_DIRECT_JMP)
			{
#ifndef _WIN64
				if (ref->instructionSize == 5)
				{
					patchBytes = directImportsJumpTableRVA - (ref->addressVA - ImageBase) - 5;
					patchDirectImportInDump32(1, 5, patchBytes, memory, memorySize, false, patchOffset, sectionRVA);
				}
#endif
			}
			else if (ref->type == IAT_REFERENCE_DIRECT_PUSH || ref->type == IAT_REFERENCE_DIRECT_MOV)
			{
#ifndef _WIN64
				if (ref->instructionSize == 5) //for x86
				{
					patchBytes = directImportsJumpTableRVA + stdImagebase;
					patchDirectImportInDump32(1, 5, patchBytes, memory, memorySize, true, patchOffset, sectionRVA);				
				}
#else
				if (ref->instructionSize == 10) //for x64
				{
				    const DWORD_PTR patchBytes64 = directImportsJumpTableRVA + stdImagebase;
					patchDirectImportInDump64(2, 10, patchBytes64, memory, memorySize, true, patchOffset, sectionRVA);
				}
#endif
			}
			else if (ref->type == IAT_REFERENCE_DIRECT_LEA)
			{
#ifndef _WIN64
				if (ref->instructionSize == 6)
				{
					patchBytes = directImportsJumpTableRVA + stdImagebase;
					patchDirectImportInDump32(2, 6, patchBytes, memory, memorySize, true, patchOffset, sectionRVA);
				}
#endif
			}
		}
	}
}

void IATReferenceScan::patchDirectJumpTable( DWORD_PTR stdImagebase, DWORD directImportsJumpTableRVA, PeParser * peParser, BYTE * jmpTableMemory, DWORD newIatBase )
{

	std::set<DWORD_PTR> apiPointers;
	for (auto& iter : iatDirectImportList)
	{
		IATReference * ref = &iter;
		apiPointers.insert(ref->targetPointer);
	}

	DWORD patchBytes;

	for (std::_Tree_const_iterator<std::_Tree_val<std::_Tree_simple_types<unsigned long>>>::value_type apiPointer :
	     apiPointers)
	{
		DWORD_PTR refTargetPointer = apiPointer;
		if (newIatBase) //create new iat in section
		{
			refTargetPointer = apiPointer - IatAddressVA + newIatBase + ImageBase;
		}
		//create jump table in section
	    const DWORD_PTR newIatAddressPointer = refTargetPointer - ImageBase + stdImagebase;

#ifdef _WIN64
		patchBytes = static_cast<DWORD>(newIatAddressPointer - (directImportsJumpTableRVA + stdImagebase) - 6);
#else
		patchBytes = newIatAddressPointer;
		DWORD relocOffset = (directImportsJumpTableRVA + 2);
		directImportLog.log(TEXT("Relocation direct imports fix: Base RVA %08X Type HIGHLOW Offset %04X RelocTableEntry %04X"), relocOffset & 0xFFFFF000, relocOffset & 0x00000FFF, (IMAGE_REL_BASED_HIGHLOW << 12) + (relocOffset & 0x00000FFF));
#endif
		jmpTableMemory[0] = 0xFF;
		jmpTableMemory[1] = 0x25;
		*reinterpret_cast<DWORD *>(&jmpTableMemory[2]) = patchBytes;

		patchDirectJumpTableEntry(apiPointer, stdImagebase, directImportsJumpTableRVA, peParser, jmpTableMemory, newIatBase);

		jmpTableMemory += 6;
		directImportsJumpTableRVA += 6;
	}
}

void IATReferenceScan::patchDirectImportInDump32( int patchPreFixBytes, int instructionSize, DWORD patchBytes, BYTE * memory, DWORD memorySize, bool generateReloc, DWORD patchOffset, DWORD sectionRVA )
{
	if (memorySize < static_cast<DWORD>(patchOffset + instructionSize))
	{
		Scylla::debugLog.log(TEXT("Error - Cannot fix direct import reference RVA: %X"), sectionRVA + patchOffset);
	}
	else
	{
		memory += patchOffset + patchPreFixBytes;
		if (generateReloc)
		{
		    const DWORD relocOffset = sectionRVA + patchOffset+ patchPreFixBytes;
			directImportLog.log(TEXT("Relocation direct imports fix: Base RVA %08X Type HIGHLOW Offset %04X RelocTableEntry %04X"), relocOffset & 0xFFFFF000, relocOffset & 0x00000FFF, (IMAGE_REL_BASED_HIGHLOW << 12) + (relocOffset & 0x00000FFF));
		}

		*reinterpret_cast<DWORD *>(memory) = patchBytes;
	}
}

void IATReferenceScan::patchDirectImportInDump64( int patchPreFixBytes, int instructionSize, DWORD_PTR patchBytes, BYTE * memory, DWORD memorySize, bool generateReloc, DWORD patchOffset, DWORD sectionRVA )
{
	if (memorySize < static_cast<DWORD>(patchOffset + instructionSize))
	{
		Scylla::debugLog.log(TEXT("Error - Cannot fix direct import reference RVA: %X"), sectionRVA + patchOffset);
	}
	else
	{
		memory += patchOffset + patchPreFixBytes;
		if (generateReloc)
		{
		    const DWORD relocOffset = sectionRVA + patchOffset+ patchPreFixBytes;
			directImportLog.log(TEXT("Relocation direct imports fix: Base RVA %08X Type DIR64 Offset %04X RelocTableEntry %04X"), relocOffset & 0xFFFFF000, relocOffset & 0x00000FFF, (IMAGE_REL_BASED_DIR64 << 12) + (relocOffset & 0x00000FFF));
		}

		*reinterpret_cast<DWORD_PTR *>(memory) = patchBytes;
	}
}

DWORD IATReferenceScan::addAdditionalApisToList()
{
	std::set<DWORD_PTR> apiPointers;

	for (auto& iter : iatDirectImportList)
	{
		IATReference * ref = &iter;

		if (ref->targetPointer == 0)
		{
			apiPointers.insert(ref->targetAddressInIat);
		}
	}

	DWORD_PTR iatAddy = IatAddressVA + IatSize;
	DWORD newIatSize = IatSize;

	bool isSuspect = false;
	for (std::_Tree_const_iterator<std::_Tree_val<std::_Tree_simple_types<unsigned long>>>::value_type apiPointer :
	     apiPointers)
	{
		for (auto& iter : iatDirectImportList)
		{
			IATReference * ref = &iter;

			if (ref->targetPointer == 0  && ref->targetAddressInIat == apiPointer)
			{
				ref->targetPointer = iatAddy;
				ApiInfo * apiInfo = apiReader->getApiByVirtualAddress(ref->targetAddressInIat, &isSuspect);
				apiReader->addFoundApiToModuleList(iatAddy, apiInfo, true, isSuspect);
			}
		}

		iatAddy += sizeof(DWORD_PTR);
		newIatSize += sizeof(DWORD_PTR);
	}

	return newIatSize;
}
