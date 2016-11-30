#include "FunctionExport.h"
#include "PeParser.h"
#include "ProcessAccessHelp.h"
#include "Scylla.h"
#include "Architecture.h"
#include "ProcessLister.h"
#include "ApiReader.h"
#include "IATSearch.h"
#include "ImportRebuilder.h"
#include "MainGui.h"


extern HINSTANCE hDllModule;

/*
Dump target process into output file.
@param fileToDump : path to file to dump
@param imagebase : Process image base (why ??)
@param entrypoint : Process entry point (or estimated entry point ?)
@param fileResult

*/
BOOL DumpProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult);


int InitializeGui(HINSTANCE hInstance, LPARAM param);


const WCHAR *  ScyllaVersionInformationW()
{
	return APPNAME L" " ARCHITECTURE L" " APPVERSION;
}

const char *  ScyllaVersionInformationA()
{
	return APPNAME_S " " ARCHITECTURE_S " " APPVERSION_S;
}

DWORD  ScyllaVersionInformationDword()
{
	return APPVERSIONDWORD;
}

BOOL DumpProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	PeParser * peFile = 0;

	if (fileToDump)
	{
		peFile = new PeParser(fileToDump, true);
	}
	else
	{
		peFile = new PeParser(imagebase, true);
	}

	bool result = peFile->dumpProcess(imagebase, entrypoint, fileResult);

	delete peFile;
	return result;
}

BOOL  ScyllaRebuildFileW(const WCHAR * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
{
	if (createBackup)
	{
		if (!ProcessAccessHelp::createBackupFile(fileToRebuild))
		{
			return FALSE;
		}
	}

	PeParser peFile(fileToRebuild, true);
	if (peFile.readPeSectionsFromFile())
	{
		peFile.setDefaultFileAlignment();
		if (removeDosStub)
		{
			peFile.removeDosStub();
		}
		peFile.alignAllSectionHeaders();
		peFile.fixPeHeader();

		if (peFile.savePeFileToDisk(fileToRebuild))
		{
			if (updatePeHeaderChecksum)
			{
				PeParser::updatePeHeaderChecksum(fileToRebuild, (DWORD)ProcessAccessHelp::getFileSize(fileToRebuild));
			}
			return TRUE;
		}
	}

	return FALSE;
}

BOOL  ScyllaRebuildFileA(const char * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
{
	WCHAR fileToRebuildW[MAX_PATH];
	if (MultiByteToWideChar(CP_ACP, 0, fileToRebuild, -1, fileToRebuildW, _countof(fileToRebuildW)) == 0)
	{
		return FALSE;
	}

	return ScyllaRebuildFileW(fileToRebuildW, removeDosStub, updatePeHeaderChecksum, createBackup);
}

BOOL  ScyllaDumpCurrentProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	ProcessAccessHelp::setCurrentProcessAsTarget();

	return DumpProcessW(fileToDump, imagebase, entrypoint, fileResult);
}

BOOL  ScyllaDumpProcessW(DWORD_PTR pid, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	if (ProcessAccessHelp::openProcessHandle((DWORD)pid))
	{
		return DumpProcessW(fileToDump, imagebase, entrypoint, fileResult);
	}
	else
	{
		return FALSE;
	}	
}

BOOL  ScyllaDumpCurrentProcessA(const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult)
{
	WCHAR fileToDumpW[MAX_PATH];
	WCHAR fileResultW[MAX_PATH];

	if (fileResult == 0)
	{
		return FALSE;
	}

	if (MultiByteToWideChar(CP_ACP, 0, fileResult, -1, fileResultW, _countof(fileResultW)) == 0)
	{
		return FALSE;
	}

	if (fileToDump != 0)
	{
		if (MultiByteToWideChar(CP_ACP, 0, fileToDump, -1, fileToDumpW, _countof(fileToDumpW)) == 0)
		{
			return FALSE;
		}

		return ScyllaDumpCurrentProcessW(fileToDumpW, imagebase, entrypoint, fileResultW);
	}
	else
	{
		return ScyllaDumpCurrentProcessW(0, imagebase, entrypoint, fileResultW);
	}
}

BOOL  ScyllaDumpProcessA(DWORD_PTR pid, const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult)
{
	WCHAR fileToDumpW[MAX_PATH];
	WCHAR fileResultW[MAX_PATH];

	if (fileResult == 0)
	{
		return FALSE;
	}

	if (MultiByteToWideChar(CP_ACP, 0, fileResult, -1, fileResultW, _countof(fileResultW)) == 0)
	{
		return FALSE;
	}

	if (fileToDump != 0)
	{
		if (MultiByteToWideChar(CP_ACP, 0, fileToDump, -1, fileToDumpW, _countof(fileToDumpW)) == 0)
		{
			return FALSE;
		}

		return ScyllaDumpProcessW(pid, fileToDumpW, imagebase, entrypoint, fileResultW);
	}
	else
	{
		return ScyllaDumpProcessW(pid, 0, imagebase, entrypoint, fileResultW);
	}
}

INT  ScyllaStartGui(DWORD dwProcessId, HINSTANCE mod, DWORD_PTR entrypoint)
{
	GUI_DLL_PARAMETER guiParam;
	guiParam.dwProcessId = dwProcessId;
	guiParam.mod = mod;
	guiParam.entrypoint = entrypoint;

	return InitializeGui(hDllModule, (LPARAM)&guiParam);
}

int  ScyllaIatSearch(DWORD dwProcessId, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch)
{
	ApiReader apiReader;
	ProcessLister processLister;
	Process *processPtr = 0;
	IATSearch iatSearch;

	// Close previous context. FIX ME : use a dedicated structure to store Scylla's context instead of globals
	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();

	if (!ProcessAccessHelp::openProcessHandle(dwProcessId))
	{
		return SCY_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
	ProcessAccessHelp::selectedModule = 0;
	

	apiReader.readApisFromModuleList();

	int retVal = SCY_ERROR_IATNOTFOUND;
	if (iatSearch.searchImportAddressTableInProcess(searchStart, iatStart, iatSize, TRUE == advancedSearch))
	{
		retVal = SCY_ERROR_SUCCESS;
	}
	
	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();

	return retVal;
}


int  ScyllaIatFixAutoW(DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR * dumpFile, const WCHAR * iatFixFile)
{
	ApiReader apiReader;
	Process *processPtr = 0;
	std::map<DWORD_PTR, ImportModuleThunk> moduleList;


	if(!processPtr) return SCY_ERROR_PIDNOTFOUND;

	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();

	if (!ProcessAccessHelp::openProcessHandle(processPtr->PID))
	{
		return SCY_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
	ProcessAccessHelp::selectedModule = 0;

	apiReader.readApisFromModuleList();

	apiReader.readAndParseIAT(iatAddr, iatSize, moduleList);

	//add IAT section to dump
	ImportRebuilder importRebuild(dumpFile);
	importRebuild.enableOFTSupport();

	int retVal = SCY_ERROR_IATWRITE;

	if (importRebuild.rebuildImportTable(iatFixFile, moduleList))
	{
		retVal = SCY_ERROR_SUCCESS;
	}

	moduleList.clear();
	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();

	return retVal;
}
