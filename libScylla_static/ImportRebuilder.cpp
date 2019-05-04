
#include "ImportRebuilder.h"
#include "Scylla.h"
#include "StringConversion.h"



/*
New Scylla section contains:

1. (optional) direct imports jump table
2. (optional) new iat
3. (optional) OFT
4. Normal IAT entries

*/

bool ImportRebuilder::rebuildImportTable(LPCTSTR newFilePath, std::map<DWORD_PTR, ImportModuleThunk> & moduleList)
{
	bool retValue = false;

	std::map<DWORD_PTR, ImportModuleThunk> copyModule;
	copyModule.insert(moduleList.begin(), moduleList.end());

	if (isValidPeFile())
	{
		if (readPeSectionsFromFile())
		{
			setDefaultFileAlignment();

			retValue = buildNewImportTable(copyModule);

			if (retValue)
			{
				alignAllSectionHeaders();
				fixPeHeader();

				if (newIatInSection)
				{
					patchFileForNewIatLocation();
				}

				if (BuildDirectImportsJumpTable)
				{
					patchFileForDirectImportJumpTable();
				}

				retValue = savePeFileToDisk(newFilePath);
			}
		}
	}

	return retValue;
}

bool ImportRebuilder::buildNewImportTable(std::map<DWORD_PTR, ImportModuleThunk> & moduleList)
{
	createNewImportSection(moduleList);

	importSectionIndex = listPeSection.size() - 1;

	if (BuildDirectImportsJumpTable)
	{
		directImportsJumpTableRVA = listPeSection[importSectionIndex].sectionHeader.VirtualAddress;
		JMPTableMemory = listPeSection[importSectionIndex].data;
	}

	if (newIatInSection)
	{
		newIatBaseAddressRVA = listPeSection[importSectionIndex].sectionHeader.VirtualAddress;

		if (BuildDirectImportsJumpTable)
		{
			newIatBaseAddressRVA += iatReferenceScan->getSizeInBytesOfJumpTableInSection();
		}

		changeIatBaseAddress(moduleList);
	}

    const DWORD dwSize = fillImportSection(moduleList);

	if (!dwSize)
	{
		return false;
	}

	setFlagToIATSection((*moduleList.begin()).second.firstThunk);

	DWORD vaImportAddress = listPeSection[importSectionIndex].sectionHeader.VirtualAddress;

	if (useOFT)
	{
		//OFT array is at the beginning of the import section
		vaImportAddress += static_cast<DWORD>(sizeOfOFTArray);
	}
	if (newIatInSection)
	{
		vaImportAddress += static_cast<DWORD>(IatSize);
	}

	if (BuildDirectImportsJumpTable)
	{
		vaImportAddress += static_cast<DWORD>(iatReferenceScan->getSizeInBytesOfJumpTableInSection());
	}

	if (isPE32())
	{
		pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = vaImportAddress;
		pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = static_cast<DWORD>(numberOfImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	else
	{
		pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = vaImportAddress;
		pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = static_cast<DWORD>(numberOfImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

	return true;
}

bool ImportRebuilder::createNewImportSection(std::map<DWORD_PTR, ImportModuleThunk> & moduleList)
{
	char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};

    const LPCTSTR sectionNameW = Scylla::config[IAT_SECTION_NAME].getString();

	calculateImportSizes(moduleList);

	if (_tcslen(sectionNameW) > IMAGE_SIZEOF_SHORT_NAME)
	{
		strcpy_s(sectionName, ".SCY");
	}
	else
	{
		StringConversion::ToCStr(sectionNameW, sectionName, _countof(sectionName));
	}

	if (newIatInSection)
	{
		sizeOfImportSection += IatSize;
	}
	if (BuildDirectImportsJumpTable)
	{
		sizeOfImportSection += iatReferenceScan->getSizeInBytesOfJumpTableInSection();
	}
	
	return addNewLastSection(sectionName, static_cast<DWORD>(sizeOfImportSection), nullptr);
}

void ImportRebuilder::setFlagToIATSection(DWORD_PTR iatAddress)
{
	for (auto& i : listPeSection)
	{
		if ((i.sectionHeader.VirtualAddress <= iatAddress) && ((i.sectionHeader.VirtualAddress + i.sectionHeader.Misc.VirtualSize) > iatAddress))
		{
			//section must be read and writeable
		    i.sectionHeader.Characteristics |= IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;
		}
	}
}

DWORD ImportRebuilder::fillImportSection(std::map<DWORD_PTR, ImportModuleThunk> & moduleList)
{
    PIMAGE_THUNK_DATA pThunk;

    BYTE * sectionData = listPeSection[importSectionIndex].data;
	DWORD offset = 0;
	DWORD offsetOFTArray = 0;

	/*
	New Scylla section contains:

	1. (optional) direct imports jump table
	2. (optional) new iat
	3. (optional) OFT
	4. Normal IAT entries

	*/
	if (BuildDirectImportsJumpTable)
	{
		offset += iatReferenceScan->getSizeInBytesOfJumpTableInSection();
		offsetOFTArray += iatReferenceScan->getSizeInBytesOfJumpTableInSection();
	}
	if (newIatInSection)
	{
		offset += IatSize; //new iat at the beginning
		offsetOFTArray += IatSize;
		memset(sectionData, 0xFF, offset);
	}
	if (useOFT)
	{
		offset += static_cast<DWORD>(sizeOfOFTArray); //size includes null termination
	}

	pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<DWORD_PTR>(sectionData) + offset);

	//skip the IMAGE_IMPORT_DESCRIPTOR
	offset += static_cast<DWORD>(numberOfImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR));

	for (auto& mapIt : moduleList)
	{
		ImportModuleThunk * importModuleThunk = &(mapIt.second);

		size_t stringLength = addImportDescriptor(importModuleThunk, offset, offsetOFTArray);
		Scylla::debugLog.log(TEXT("fillImportSection :: importDesc.Name %X"), pImportDescriptor->Name);


		offset += static_cast<DWORD>(stringLength); //stringLength has null termination char

	    auto pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<DWORD_PTR>(sectionData) + offset);

		//pThunk = (PIMAGE_THUNK_DATA)(getMemoryPointerFromRVA(importModuleThunk->firstThunk));

		DWORD_PTR lastRVA = importModuleThunk->firstThunk - sizeof(DWORD_PTR);

		for ( std::map<DWORD_PTR, ImportThunk>::iterator mapIt2 = mapIt.second.thunkList.begin() ; mapIt2 != mapIt.second.thunkList.end(); mapIt2++ )
		{
			ImportThunk * importThunk = &((*mapIt2).second);

			if (useOFT)
			{
				pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD_PTR>(sectionData) + offsetOFTArray);
				offsetOFTArray += sizeof(DWORD_PTR); //increase OFT array index
			}
			else
			{
				pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(getMemoryPointerFromRVA(importThunk->rva));
			}

			//check wrong iat pointer
			if (!pThunk)
			{
				Scylla::debugLog.log(TEXT("fillImportSection :: Failed to get pThunk RVA: %X"), importThunk->rva);
				return 0;
			}

			if (lastRVA + sizeof(DWORD_PTR) != importThunk->rva)
			{
				//add additional import desc
				addSpecialImportDescriptor(importThunk->rva, offsetOFTArray);
				if (useOFT)
				{
					pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD_PTR>(sectionData) + offsetOFTArray);
					offsetOFTArray += sizeof(DWORD_PTR); //increase OFT array index, next module
				}				
			}
			lastRVA = importThunk->rva;

			Scylla::debugLog.log(TEXT("fillImportSection :: importThunk %X pThunk %X pImportByName %X offset %X"), importThunk,pThunk,pImportByName,offset);
			stringLength = addImportToImportTable(importThunk, pThunk, pImportByName, offset);

			offset += static_cast<DWORD>(stringLength); //is 0 bei import by ordinal
			pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<DWORD_PTR>(pImportByName) + stringLength);
		}

		offsetOFTArray += sizeof(DWORD_PTR); //increase OFT array index, next module
		pImportDescriptor++;
	}

	return offset;
}

size_t ImportRebuilder::addImportDescriptor(ImportModuleThunk * pImportModule, DWORD sectionOffset, DWORD sectionOffsetOFTArray)
{
    const size_t stringLength = _tcslen(pImportModule->moduleName) + 1;
	    
	/*
		Warning: stringLength MUST include null termination char
	*/

    StringConversion::ToCStr(pImportModule->moduleName, reinterpret_cast<LPSTR>(listPeSection[importSectionIndex].data + sectionOffset), stringLength);

	pImportDescriptor->FirstThunk = static_cast<DWORD>(pImportModule->firstThunk);
	pImportDescriptor->Name = static_cast<DWORD>(convertOffsetToRVAVector(
	    listPeSection[importSectionIndex].sectionHeader.PointerToRawData + sectionOffset));
	
	if (useOFT)
	{
		pImportDescriptor->OriginalFirstThunk = static_cast<DWORD>(convertOffsetToRVAVector(
		    listPeSection[importSectionIndex].sectionHeader.PointerToRawData + sectionOffsetOFTArray));
	}

	return stringLength;
}

void ImportRebuilder::addSpecialImportDescriptor(DWORD_PTR rvaFirstThunk, DWORD sectionOffsetOFTArray)
{
    const auto oldID = pImportDescriptor;
	pImportDescriptor++;

	pImportDescriptor->FirstThunk = static_cast<DWORD>(rvaFirstThunk);
	pImportDescriptor->Name = oldID->Name;

	if (useOFT)
	{
		pImportDescriptor->OriginalFirstThunk = static_cast<DWORD>(convertOffsetToRVAVector(
		    listPeSection[importSectionIndex].sectionHeader.PointerToRawData + sectionOffsetOFTArray));
	}
}

void ImportRebuilder::calculateImportSizes(std::map<DWORD_PTR, ImportModuleThunk> & moduleList)
{
    sizeOfImportSection = 0;
	sizeOfApiAndModuleNames = 0;
	sizeOfOFTArray = 0;

	numberOfImportDescriptors = moduleList.size() + 1; //last is zero'd

	for (auto& mapIt : moduleList)
	{
		DWORD_PTR lastRVA = mapIt.second.firstThunk - sizeof(DWORD_PTR);

		sizeOfApiAndModuleNames += static_cast<DWORD>(_tcslen(mapIt.second.moduleName) + 1);

		for (auto& mapIt2 : mapIt.second.thunkList)
		{
			if (lastRVA + sizeof(DWORD_PTR) != mapIt2.second.rva)
			{
				numberOfImportDescriptors++; //add additional import desc
				sizeOfOFTArray += sizeof(DWORD_PTR) + sizeof(DWORD_PTR);
			}

			if(mapIt2.second.name[0] != '\0')
			{
				sizeOfApiAndModuleNames += sizeof(WORD); //Hint from IMAGE_IMPORT_BY_NAME
				sizeOfApiAndModuleNames += static_cast<DWORD>(_tcslen(mapIt2.second.name) + 1);
			}

			//OriginalFirstThunk Array in Import Section: value
			sizeOfOFTArray += sizeof(DWORD_PTR);

			lastRVA = mapIt2.second.rva;
		}

		//OriginalFirstThunk Array in Import Section: NULL termination
		sizeOfOFTArray += sizeof(DWORD_PTR);
	}

	sizeOfImportSection = sizeOfOFTArray + sizeOfApiAndModuleNames + numberOfImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR);
}

size_t ImportRebuilder::addImportToImportTable( ImportThunk * pImport, PIMAGE_THUNK_DATA pThunk, PIMAGE_IMPORT_BY_NAME pImportByName, DWORD sectionOffset)
{
	size_t stringLength = 0;

	if(pImport->name[0] == '\0')
	{
		pThunk->u1.AddressOfData = IMAGE_ORDINAL(pImport->ordinal) | IMAGE_ORDINAL_FLAG;
		}
		else
		{
		    pImportByName->Hint = pImport->hint;

		    stringLength = _tcslen(pImport->name) + 1;
		    StringConversion::ToCStr(pImport->name, pImportByName->Name, stringLength);
		    pThunk->u1.AddressOfData = convertOffsetToRVAVector(listPeSection[importSectionIndex].sectionHeader.PointerToRawData + sectionOffset);

		    if (!pThunk->u1.AddressOfData)
		    {
		        Scylla::debugLog.log(TEXT("addImportToImportTable :: failed to get AddressOfData %X %X"), listPeSection[importSectionIndex].sectionHeader.PointerToRawData, sectionOffset);
		    }

		    //next import should be nulled
		    pThunk++;
		    pThunk->u1.AddressOfData = 0;

		    Scylla::debugLog.log(TEXT("addImportToImportTable :: pThunk->u1.AddressOfData %X %X %X"), pThunk->u1.AddressOfData, pThunk, listPeSection[importSectionIndex].sectionHeader.PointerToRawData + sectionOffset);
		    stringLength += sizeof(WORD);
		}

		return stringLength;
		}

		BYTE * ImportRebuilder::getMemoryPointerFromRVA(DWORD_PTR dwRVA)
		{
		    const int peSectionIndex = convertRVAToOffsetVectorIndex(dwRVA);

		    if (peSectionIndex == -1)
		    {
		        return nullptr;
		    }

		    const DWORD rvaPointer = (static_cast<DWORD>(dwRVA) - listPeSection[peSectionIndex].sectionHeader.VirtualAddress);
		    DWORD minSectionSize = rvaPointer + sizeof(DWORD_PTR) * 2; //add space for 1 IAT address

		    if (listPeSection[peSectionIndex].data == 0 || listPeSection[peSectionIndex].dataSize == 0)
		    {
		        listPeSection[peSectionIndex].dataSize = minSectionSize; 
		        listPeSection[peSectionIndex].normalSize = minSectionSize;
		        listPeSection[peSectionIndex].data = new BYTE[listPeSection[peSectionIndex].dataSize];

		        listPeSection[peSectionIndex].sectionHeader.SizeOfRawData = listPeSection[peSectionIndex].dataSize;
		    }
		    else if(listPeSection[peSectionIndex].dataSize < minSectionSize)
		    {
		        auto temp = new BYTE[minSectionSize];
		        memcpy(temp, listPeSection[peSectionIndex].data, listPeSection[peSectionIndex].dataSize);
		        delete [] listPeSection[peSectionIndex].data;

		        listPeSection[peSectionIndex].data = temp;
		        listPeSection[peSectionIndex].dataSize = minSectionSize;
		        listPeSection[peSectionIndex].normalSize = minSectionSize;

		        listPeSection[peSectionIndex].sectionHeader.SizeOfRawData = listPeSection[peSectionIndex].dataSize;
		    }

		    return reinterpret_cast<BYTE *>(reinterpret_cast<DWORD_PTR>(listPeSection[peSectionIndex].data) + rvaPointer);
		}

		void ImportRebuilder::enableOFTSupport()
		{
		    useOFT = true;
		}

		void ImportRebuilder::enableNewIatInSection(DWORD_PTR iatAddress, DWORD iatSize)
		{
		    newIatInSection = true;
		    IatAddress = iatAddress;
		    IatSize = iatSize;

		    iatReferenceScan->ScanForDirectImports = false;
		    iatReferenceScan->ScanForNormalImports = true;

		    iatReferenceScan->startScan(ProcessAccessHelp::targetImageBase, static_cast<DWORD>(ProcessAccessHelp::targetSizeOfImage), IatAddress, IatSize);
		}

		void ImportRebuilder::patchFileForNewIatLocation()
		{
		    iatReferenceScan->patchNewIat(getStandardImagebase(), newIatBaseAddressRVA, static_cast<PeParser *>(this));
		}

		void ImportRebuilder::changeIatBaseAddress( std::map<DWORD_PTR, ImportModuleThunk> & moduleList )
		{
		    const DWORD_PTR oldIatRva = IatAddress - ProcessAccessHelp::targetImageBase;

		    for ( std::map<DWORD_PTR, ImportModuleThunk>::iterator mapIt = moduleList.begin() ; mapIt != moduleList.end(); mapIt++ )
		    {
		        (*mapIt).second.firstThunk = (*mapIt).second.firstThunk - oldIatRva + newIatBaseAddressRVA;

		        for ( std::map<DWORD_PTR, ImportThunk>::iterator mapIt2 = (*mapIt).second.thunkList.begin() ; mapIt2 != (*mapIt).second.thunkList.end(); mapIt2++ )
		        {
		            (*mapIt2).second.rva = (*mapIt2).second.rva - oldIatRva + newIatBaseAddressRVA;
		        }
		    }
		}

		void ImportRebuilder::patchFileForDirectImportJumpTable()
		{
		    if (newIatInSection)
		    {
		        iatReferenceScan->patchDirectJumpTable(getStandardImagebase(), directImportsJumpTableRVA, static_cast<PeParser *>(this), JMPTableMemory, newIatBaseAddressRVA);
		    }
		    else
		    {
		        iatReferenceScan->patchDirectJumpTable(getStandardImagebase(), directImportsJumpTableRVA, static_cast<PeParser *>(this), JMPTableMemory, 0);
		    }
		}
