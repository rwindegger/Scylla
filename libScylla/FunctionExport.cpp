#include "FunctionExport.h"
#include "PeParser.h"
#include "ProcessAccessHelp.h"
#include "Architecture.h"
#include "ProcessLister.h"
#include "ApiReader.h"
#include "IATSearch.h"
#include "ImportRebuilder.h"

extern HINSTANCE hDllModule;

// Internal structure of a SCY_HANDLE
typedef struct SCY_CONTEXT_T_
{
    size_t targetProcId;
    ApiReader apiReader;
} SCY_CONTEXT_T;

const WCHAR *  ScyllaVersionInformationW()
{
    return Scylla::get_version_w();
}

const char *  ScyllaVersionInformationA()
{
    return Scylla::get_version_a();
}

DWORD  ScyllaVersionInformationDword()
{
    return Scylla::get_version();
}

BOOL DumpProcessW(SCY_HANDLE hScyllaContext, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
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

BOOL  ScyllaRebuildFileW(SCY_HANDLE hScyllaContext, const WCHAR * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
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

BOOL  ScyllaRebuildFileA(SCY_HANDLE hScyllaContext, const char * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
{
    WCHAR fileToRebuildW[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, fileToRebuild, -1, fileToRebuildW, _countof(fileToRebuildW)) == 0)
    {
        return FALSE;
    }

    return ScyllaRebuildFileW(hScyllaContext, fileToRebuildW, removeDosStub, updatePeHeaderChecksum, createBackup);
}

BOOL  ScyllaDumpCurrentProcessW(SCY_HANDLE hScyllaContext, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
    //ProcessAccessHelp::setCurrentProcessAsTarget();
    return DumpProcessW(hScyllaContext, fileToDump, imagebase, entrypoint, fileResult);
}

BOOL  ScyllaDumpProcessW(DWORD_PTR pid, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
    BOOL bDumpResult;
    SCY_HANDLE hScyllaContext;

    if (!ScyllaInitContext(&hScyllaContext, pid))
        return FALSE;

    bDumpResult = DumpProcessW(hScyllaContext, fileToDump, imagebase, entrypoint, fileResult);
    ScyllaUnInitContext(hScyllaContext);

    return bDumpResult;
}

BOOL  ScyllaDumpProcessExW(DWORD_PTR pid, const WCHAR * fileResult)
{
    Scylla::processLister.setDebugPrivileges();
    auto procList = Scylla::processLister.getProcessListSnapshotNative();

    Process process{};
    for (auto procit = procList.begin(); procit != procList.end(); ++procit)
    {
        if (procit->PID == pid)
        {
            process = *procit;
            break;
        }
    }

    SCY_HANDLE hScyllaContext;

    if (!ScyllaInitContext(&hScyllaContext, process.PID))
        return ERROR_DLL_INIT_FAILED;

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
    ProcessAccessHelp::selectedModule = 0;

    ProcessAccessHelp::targetImageBase = process.imageBase;
    ProcessAccessHelp::targetSizeOfImage = process.imageSize;

    process.imageSize = static_cast<DWORD>(ProcessAccessHelp::targetSizeOfImage);

    process.entryPoint = ProcessAccessHelp::getEntryPointFromFile(process.fullPath);

    Scylla::Log->log(L"%s ImageBase 0x" PRINTF_DWORD_PTR_FULL L" ImageSize 0x%08X EntryPoint 0x" PRINTF_DWORD_PTR_FULL, process.filename, process.imageBase, process.imageSize, process.entryPoint + process.imageBase);

    PeParser peFileD(process.imageBase, true);

    BOOL bDumpResult = false;
    if (peFileD.isValidPeFile())
    {
        bDumpResult = peFileD.dumpProcess(process.imageBase, process.entryPoint + process.imageBase, fileResult);
        if (bDumpResult)
        {
            DWORD newSize = 0;
            DWORD fileSize = (DWORD)ProcessAccessHelp::getFileSize(fileResult);
            PeParser peFile(fileResult, true);
            bDumpResult = peFile.readPeSectionsFromFile();
            if (bDumpResult)
            {
                peFile.setDefaultFileAlignment();
                peFile.alignAllSectionHeaders();
                peFile.fixPeHeader();
                bDumpResult = peFile.savePeFileToDisk(fileResult);
                if (bDumpResult)
                {
                    newSize = (DWORD)ProcessAccessHelp::getFileSize(fileResult);

                    if (Scylla::config[UPDATE_HEADER_CHECKSUM].isTrue())
                    {
                        Scylla::Log->log(L"Generating PE header checksum");
                        if (!PeParser::updatePeHeaderChecksum(fileResult, newSize))
                        {
                            Scylla::Log->log(L"Generating PE header checksum FAILED!");
                        }
                    }

                    Scylla::Log->log(L"Rebuild success %s", fileResult);
                    Scylla::Log->log(L"-> Old file size 0x%08X new file size 0x%08X (%d %%)", fileSize, newSize, ((newSize * 100) / fileSize));
                }
                else
                {
                    Scylla::Log->log(L"Rebuild failed, cannot save file %s", fileResult);
                }
            }
        }
    }
    else
    {
        Scylla::Log->log(L"Error: Invalid PE file or invalid PE header. Try reading PE header from disk/process.");
    }

    ScyllaUnInitContext(hScyllaContext);
    if (bDumpResult)
        return ERROR_SUCCESS;
    else
        return ERROR_ACCESS_DENIED;
}

BOOL  ScyllaDumpCurrentProcessA(SCY_HANDLE hScyllaContext, const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult)
{
    WCHAR fileToDumpW[MAX_PATH];
    WCHAR fileResultW[MAX_PATH];
    SCY_CONTEXT_T* pPrivScyContext = (SCY_CONTEXT_T*)hScyllaContext;

    if (!pPrivScyContext)
        return FALSE;

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

        return ScyllaDumpCurrentProcessW(hScyllaContext, fileToDumpW, imagebase, entrypoint, fileResultW);
    }
    else
    {
        return ScyllaDumpCurrentProcessW(hScyllaContext, 0, imagebase, entrypoint, fileResultW);
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

int  ScyllaIatFixAutoW(SCY_HANDLE hScyllaContext, DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR * dumpFile, const WCHAR * iatFixFile)
{
    std::map<DWORD_PTR, ImportModuleThunk> moduleList;

    SCY_CONTEXT_T* pPrivScyContext = (SCY_CONTEXT_T*)hScyllaContext;

    if (!pPrivScyContext)
        return SCY_ERROR_PIDNOTFOUND;


    //ProcessAccessHelp::closeProcessHandle();
    //apiReader.clearAll();

    //if (!ProcessAccessHelp::openProcessHandle(processPtr->PID))
    //{
    //	return SCY_ERROR_PROCOPEN;
    //}

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
    ProcessAccessHelp::selectedModule = 0;

    pPrivScyContext->apiReader.readApisFromModuleList();

    pPrivScyContext->apiReader.readAndParseIAT(iatAddr, iatSize, moduleList);

    //add IAT section to dump
    ImportRebuilder importRebuild(dumpFile);
    importRebuild.enableOFTSupport();

    int retVal = SCY_ERROR_IATWRITE;

    if (importRebuild.rebuildImportTable(iatFixFile, moduleList))
    {
        retVal = SCY_ERROR_SUCCESS;
    }

    moduleList.clear();
    //ProcessAccessHelp::closeProcessHandle();
    //apiReader.clearAll();

    return retVal;
}

int  ScyllaIatSearch(SCY_HANDLE hScyllaContext, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch)
{
    return Scylla::iat_search(hScyllaContext, iatStart, iatSize, searchStart, advancedSearch);
}

BOOL ScyllaInitContext(PSCY_HANDLE phCtxt, DWORD_PTR TargetProcessPid)
{
    return Scylla::initialize_context(phCtxt, TargetProcessPid);
}

BOOL ScyllaUnInitContext(SCY_HANDLE hCtxt)
{
    return Scylla::deinitialize_context(hCtxt);
}
