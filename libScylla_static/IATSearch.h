#pragma once

#include "ApiReader.h"
#include <set>

class IATSearch : protected ApiReader
{
public:

    DWORD_PTR memoryAddress;
    SIZE_T memorySize;

    bool searchImportAddressTableInProcess(DWORD_PTR startAddress, DWORD_PTR* addressIAT, size_t* sizeIAT, bool advanced);

private:

    DWORD_PTR findAPIAddressInIAT(DWORD_PTR startAddress);
    bool findIATAdvanced(DWORD_PTR startAddress, DWORD_PTR* addressIAT, size_t* sizeIAT);
    static DWORD_PTR findNextFunctionAddress();
    static DWORD_PTR findIATPointer();
    //DWORD_PTR findAddressFromWORDString(char * stringBuffer);
    //DWORD_PTR findAddressFromNormalCALLString(char * stringBuffer);
    bool isIATPointerValid(DWORD_PTR iatPointer, bool checkRedirects);

    bool findIATStartAndSize(DWORD_PTR address, DWORD_PTR * addressIAT, size_t *sizeIAT) const;

    DWORD_PTR findIATStartAddress(DWORD_PTR baseAddress, DWORD_PTR startAddress, BYTE * dataBuffer) const;
    size_t findIATSize(DWORD_PTR baseAddress, DWORD_PTR iatAddress, BYTE * dataBuffer, size_t bufferSize) const;

    void findIATPointers(std::set<DWORD_PTR> & iatPointers);
    static void findExecutableMemoryPagesByStartAddress(DWORD_PTR startAddress, DWORD_PTR* baseAddress, SIZE_T* memorySize);
    void filterIATPointersList(std::set<DWORD_PTR> & iatPointers);
    static void getMemoryBaseAndSizeForIat(DWORD_PTR address, DWORD_PTR* baseAddress, DWORD* baseSize);
};
