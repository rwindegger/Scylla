#pragma once

#include <windows.h>
#include <vector>

class PeSection
{
public:
    TCHAR name[IMAGE_SIZEOF_SHORT_NAME + 1];
    DWORD_PTR virtualAddress;
    DWORD  virtualSize;
    DWORD  rawAddress;
    DWORD  rawSize;
    DWORD characteristics;

    bool isDumped;

    bool highlightVirtualSize() const;
};

class PeFileSection {
public:
	IMAGE_SECTION_HEADER sectionHeader{};
	BYTE * data;
	DWORD dataSize;
	DWORD normalSize;

	PeFileSection()
	{
		ZeroMemory(&sectionHeader, sizeof(IMAGE_SECTION_HEADER));
		data = nullptr;
		dataSize = 0;
		normalSize = 0;
	}
};

class PeParser
{
public:
	PeParser(LPCTSTR file, bool readSectionHeaders = true);
	PeParser(DWORD_PTR moduleBase, bool readSectionHeaders = true);

	~PeParser();

	bool isValidPeFile() const;
	bool isPE64() const;
	bool isPE32() const;

	bool isTargetFileSamePeFormat() const;

	WORD getNumberOfSections() const;
	std::vector<PeFileSection> & getSectionHeaderList();

	bool hasExportDirectory() const;
	bool hasTLSDirectory() const;
	bool hasRelocationDirectory() const;
	bool hasOverlayData();

	DWORD getEntryPoint() const;

	bool getSectionName(int sectionIndex, LPTSTR output, int outputLen);

	DWORD getSectionHeaderBasedFileSize();
	DWORD getSectionHeaderBasedSizeOfImage();

	bool readPeSectionsFromProcess();
	bool readPeSectionsFromFile();
	bool savePeFileToDisk(LPCTSTR newFile);
	void removeDosStub();
	void alignAllSectionHeaders();
	void fixPeHeader();
	void setDefaultFileAlignment() const;
	bool dumpProcess(DWORD_PTR modBase, DWORD_PTR entryPoint, LPCTSTR dumpFilePath);
	bool dumpProcess(DWORD_PTR modBase, DWORD_PTR entryPoint, LPCTSTR dumpFilePath, std::vector<PeSection> & sectionList);

	void setEntryPointVa(DWORD_PTR entryPoint) const;
	void setEntryPointRva(DWORD entryPoint) const;

	static bool updatePeHeaderChecksum(LPCTSTR targetFile, DWORD fileSize);
	BYTE * getSectionMemoryByIndex(int index);
	DWORD getSectionMemorySizeByIndex(int index);
	int convertRVAToOffsetVectorIndex(DWORD_PTR dwRVA);
	DWORD_PTR convertOffsetToRVAVector(DWORD_PTR dwOffset);
	DWORD_PTR convertRVAToOffsetVector(DWORD_PTR dwRVA);
	DWORD_PTR convertRVAToOffsetRelative(DWORD_PTR dwRVA);
	DWORD getSectionAddressRVAByIndex( int index );

    PIMAGE_NT_HEADERS getCurrentNtHeader() const;
protected:
	PeParser();


	static const DWORD FileAlignmentConstant = 0x200;

    LPCTSTR filename{};
	DWORD_PTR moduleBaseAddress{};

	/************************************************************************/
	/* PE FILE                                                              */
	/*                                                                      */
	/*  IMAGE_DOS_HEADER      64   0x40                                     */
	/*	IMAGE_NT_HEADERS32   248   0xF8                                     */
	/*	IMAGE_NT_HEADERS64   264  0x108                                     */
	/*	IMAGE_SECTION_HEADER  40   0x28                                     */
	/************************************************************************/

	PIMAGE_DOS_HEADER pDosHeader{};
	BYTE * pDosStub{}; //between dos header and section header
	DWORD dosStubSize{};
	PIMAGE_NT_HEADERS32 pNTHeader32{};
	PIMAGE_NT_HEADERS64 pNTHeader64{};
	std::vector<PeFileSection> listPeSection;
	BYTE * overlayData{};
	DWORD overlaySize{};
	/************************************************************************/

	BYTE * fileMemory{};
	BYTE * headerMemory{};

	HANDLE hFile{};
	DWORD fileSize{};

	bool readPeHeaderFromFile(bool readSectionHeaders);
	bool readPeHeaderFromProcess(bool readSectionHeaders);

	bool hasDirectory(int directoryIndex) const;
	bool getSectionHeaders();
	void getDosAndNtHeader(BYTE * memory, LONG size);
	DWORD calcCorrectPeHeaderSize( bool readSectionHeaders ) const;
    static DWORD getInitialHeaderReadSize( bool readSectionHeaders );
	bool openFileHandle();
	void closeFileHandle();
	void initClass();

    static DWORD isMemoryNotNull(const BYTE * data, int dataSize );
	bool openWriteFileHandle(LPCTSTR newFile );
    static bool writeZeroMemoryToFile(HANDLE hFile, DWORD fileOffset, DWORD size);

	bool readPeSectionFromFile( DWORD readOffset, PeFileSection & peFileSection ) const;
    static bool readPeSectionFromProcess( DWORD_PTR readOffset, PeFileSection & peFileSection );

	bool readSectionFromProcess(DWORD_PTR readOffset, PeFileSection & peFileSection ) const;
	bool readSectionFromFile(DWORD readOffset, PeFileSection & peFileSection ) const;
	bool readSectionFrom(DWORD_PTR readOffset, PeFileSection & peFileSection, bool isProcess) const;

	
	DWORD_PTR getStandardImagebase() const;

	bool addNewLastSection(LPCSTR sectionName, DWORD sectionSize, BYTE * sectionData);
    static DWORD alignValue(DWORD badValue, DWORD alignTo);

	void setNumberOfSections(WORD numberOfSections) const;
	
	void removeIatDirectory();
	bool getFileOverlay();
	
};
