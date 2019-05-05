#pragma once

#include <Windows.h>
#include <cstdlib>

enum ReBaseErr
{
	RB_OK = 0,
	RB_INVALIDPE,
	RB_NORELOCATIONINFO,
	RB_INVALIDRVA,
	RB_INVALIDNEWBASE,
	RB_ACCESSVIOLATION
};

/*****************************************************************************
  Improved Realign DLL version 1.5 by yoda
*****************************************************************************/

class PeRebuild
{
public:

    static bool truncateFile(LPCTSTR szFilePath, DWORD dwNewFsize);
	DWORD realignPE(LPVOID AddressOfMapFile,DWORD dwFsize);
    static DWORD wipeReloc(void* pMap, DWORD dwFsize);
    static bool validatePE(void* pPEImage, DWORD dwFileSize);
    static ReBaseErr reBasePEImage(void* pPE, DWORD_PTR dwNewBase);

    static bool updatePeHeaderChecksum(LPVOID AddressOfMapFile, DWORD dwFsize);

	LPVOID createFileMappingViewFull(LPCTSTR filePath);
	void closeAllMappingHandles();

private:

	// constants
	static const size_t MAX_SEC_NUM = 30;

	static const DWORD ScanStartDS = 0x40;
	static const int MinSectionTerm = 5;
	static const int FileAlignmentConstant = 0x200;

	// variables
	DWORD_PTR            dwMapBase;
	LPVOID               pMap;
	DWORD				 dwTmpNum,dwSectionBase;
	WORD                 wTmpNum;
	CHAR *	             pCH;
	WORD *			     pW;
	DWORD *				 pDW;
	LPVOID               pSections[MAX_SEC_NUM];

	//my vars
	HANDLE hFileToMap;
	HANDLE hMappedFile;
	LPVOID addrMappedDll;


	DWORD validAlignment(DWORD BadSize) const;
    static DWORD validAlignmentNew(DWORD badAddress);
    static bool isRoundedTo(DWORD_PTR dwTarNum, DWORD_PTR dwRoundNum);

	void cleanSectionPointer();
    static bool validatePeHeaders( PIMAGE_DOS_HEADER pDosh );
};
