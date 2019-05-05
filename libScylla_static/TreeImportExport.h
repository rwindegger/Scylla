#pragma once

#include <windows.h>
#include "ProcessLister.h"
#include "Thunks.h"
#include <tinyxml2.h>

class TreeImportExport
{
public:

	TreeImportExport(LPCTSTR targetXmlFile);

	bool exportTreeList(const std::map<DWORD_PTR, ImportModuleThunk> & moduleList, const Process * process, DWORD_PTR addressOEP, DWORD_PTR addressIAT, DWORD sizeIAT) ;
	bool importTreeList(std::map<DWORD_PTR, ImportModuleThunk> & moduleList, DWORD_PTR * addressOEP, DWORD_PTR * addressIAT, DWORD * sizeIAT);

private:

	TCHAR xmlPath[MAX_PATH]{};

	char xmlStringBuffer[MAX_PATH];

	void setTargetInformation(tinyxml2::XMLElement * rootElement, const Process * process, DWORD_PTR addressOEP, DWORD_PTR addressIAT, DWORD sizeIAT);
	void addModuleListToRootElement(tinyxml2::XMLDocument& doc, tinyxml2::XMLElement * rootElement, const std::map<DWORD_PTR, ImportModuleThunk> & moduleList);

	void parseAllElementModules(tinyxml2::XMLElement * targetElement, std::map<DWORD_PTR, ImportModuleThunk> & moduleList);
	void parseAllElementImports(tinyxml2::XMLElement * moduleElement, ImportModuleThunk * importModuleThunk) const;

	tinyxml2::XMLElement * getModuleXmlElement(tinyxml2::XMLDocument& doc, const ImportModuleThunk * importModuleThunk);
    tinyxml2::XMLElement * getImportXmlElement(tinyxml2::XMLDocument& doc, const ImportThunk * importThunk);

    static bool saveXmlToFile(tinyxml2::XMLDocument& doc, LPCTSTR xmlFilePath);
    static bool readXmlFile(tinyxml2::XMLDocument& doc, LPCTSTR xmlFilePath);

	void ConvertBoolToString(bool boolValue);
	void ConvertWordToString(WORD dwValue);
	void ConvertDwordPtrToString(DWORD_PTR dwValue);

    static DWORD_PTR ConvertStringToDwordPtr(const char * strValue);
    static WORD ConvertStringToWord(const char * strValue);
    static bool ConvertStringToBool(const char * strValue);
};
