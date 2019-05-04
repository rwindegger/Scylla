#pragma once

#include <windows.h>
#include <map>
//#include <hash_map>
#include <unordered_map>
#include "ProcessAccessHelp.h"
#include "Thunks.h"

typedef std::pair<DWORD_PTR, ApiInfo *> API_Pair;

class ApiReader : public ProcessAccessHelp
{
public:
    //static stdext::hash_multimap<DWORD_PTR, ApiInfo *> apiList; //api look up table
    static std::unordered_multimap<DWORD_PTR, ApiInfo *> apiList; //api look up table

    static std::map<DWORD_PTR, ImportModuleThunk> * moduleThunkList; //store found apis

    static DWORD_PTR minApiAddress;
    static DWORD_PTR maxApiAddress;

    /*
     * Read all APIs from target process
     */
    void readApisFromModuleList();

    bool isApiAddressValid(DWORD_PTR virtualAddress) const;
    ApiInfo * getApiByVirtualAddress(DWORD_PTR virtualAddress, bool * isSuspect);
    void readAndParseIAT(DWORD_PTR addressIAT, DWORD sizeIAT, std::map<DWORD_PTR, ImportModuleThunk> &moduleListNew);
    void addFoundApiToModuleList(DWORD_PTR iatAddress, ApiInfo * apiFound, bool isNewModule, bool isSuspect);
    void clearAll() const;
    static bool isInvalidMemoryForIat(DWORD_PTR address);
private:
    bool readExportTableAlwaysFromDisk = false;
    void parseIAT(DWORD_PTR addressIAT, BYTE * iatBuffer, SIZE_T size);

    void addApi(LPCTSTR functionName, WORD hint, WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo *moduleInfo) const;
    void addApiWithoutName(WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo *moduleInfo) const;
    static inline bool isApiForwarded(DWORD_PTR rva, PIMAGE_NT_HEADERS pNtHeader);
    void handleForwardedApi(DWORD_PTR vaStringPointer, LPCTSTR functionNameParent, DWORD_PTR rvaParent, WORD ordinalParent, ModuleInfo *moduleParent) const;
    void parseModule(ModuleInfo *module) const;
    void parseModuleWithProcess(ModuleInfo * module) const;

    void parseExportTable(ModuleInfo *module, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress) const;

    ModuleInfo * findModuleByName(LPTSTR name) const;

    void findApiByModuleAndOrdinal(ModuleInfo * module, WORD ordinal, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const;
    void findApiByModuleAndName(ModuleInfo * module, LPCTSTR searchFunctionName, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const;
    void findApiByModule(ModuleInfo * module, LPCTSTR searchFunctionName, WORD ordinal, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const;

    bool isModuleLoadedInOwnProcess(ModuleInfo * module) const;
    void parseModuleWithOwnProcess(ModuleInfo * module) const;
    static bool isPeAndExportTableValid(PIMAGE_NT_HEADERS pNtHeader);
    void findApiInProcess(ModuleInfo * module, LPCTSTR searchFunctionName, WORD ordinal, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const;
    bool findApiInExportTable(ModuleInfo *module, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress, LPCTSTR searchFunctionName, WORD ordinal, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const;

    static BYTE * getHeaderFromProcess(ModuleInfo * module);
    static BYTE * getExportTableFromProcess(ModuleInfo * module, PIMAGE_NT_HEADERS pNtHeader);

    static void setModulePriority(ModuleInfo * module);
    static void setMinMaxApiAddress(DWORD_PTR virtualAddress);

    void parseModuleWithMapping(ModuleInfo *moduleInfo) const; //not used

    bool addModuleToModuleList(LPCTSTR moduleName, DWORD_PTR firstThunk);
    bool addFunctionToModuleList(ApiInfo * apiFound, DWORD_PTR va, DWORD_PTR rva, WORD ordinal, bool valid, bool suspect);
    bool addNotFoundApiToModuleList(DWORD_PTR iatAddressVA, DWORD_PTR apiAddress);

    void addUnknownModuleToModuleList(DWORD_PTR firstThunk);
    static bool isApiBlacklisted(LPCTSTR functionName);
    bool isWinSxSModule(ModuleInfo * module) const;

    //ApiInfo * getScoredApi(stdext::hash_map<DWORD_PTR, ApiInfo *>::iterator it1,size_t countDuplicates, bool hasName, bool hasUnicodeAnsiName, bool hasNoUnderlineInName, bool hasPrioDll,bool hasPrio0Dll,bool hasPrio1Dll, bool hasPrio2Dll, bool firstWin );
    ApiInfo * getScoredApi(std::unordered_map<DWORD_PTR, ApiInfo *>::iterator it1, size_t countDuplicates, bool hasName, bool hasUnicodeAnsiName, bool hasNoUnderlineInName, bool hasPrioDll, bool hasPrio0Dll, bool hasPrio1Dll, bool hasPrio2Dll, bool firstWin);
};
