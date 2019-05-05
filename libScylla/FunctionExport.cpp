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
    size_t targetProcId{};
    ApiReader apiReader;
} SCY_CONTEXT_T;

LPCTSTR GetVersionInformation()
{
    return Scylla::get_version_information();
}

DWORD GetVersionNumber()
{
    return Scylla::get_version();
}

BOOL _dumpProcess(SCY_HANDLE hScyllaContext, LPCTSTR fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, LPCTSTR fileResult)
{
    PeParser * peFile;

    if (fileToDump)
    {
        peFile = new PeParser(fileToDump, true);
    }
    else
    {
        peFile = new PeParser(imagebase, true);
    }

    const bool result = peFile->dumpProcess(imagebase, entrypoint, fileResult);

    delete peFile;
    return result;
}

BOOL RebuildFile(SCY_HANDLE hScyllaContext, LPCTSTR fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
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

BOOL DumpCurrentProcess(SCY_HANDLE hScyllaContext, LPCTSTR fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, LPCTSTR fileResult)
{
    //ProcessAccessHelp::setCurrentProcessAsTarget();
    return _dumpProcess(hScyllaContext, fileToDump, imagebase, entrypoint, fileResult);
}

BOOL DumpProcess(DWORD_PTR pid, LPCTSTR fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, LPCTSTR fileResult)
{
    SCY_HANDLE hScyllaContext;

    if (!InitContext(&hScyllaContext, pid))
        return FALSE;

    BOOL bDumpResult = _dumpProcess(hScyllaContext, fileToDump, imagebase, entrypoint, fileResult);
    DeinitializeContext(hScyllaContext);

    return bDumpResult;
}

BOOL DumpProcessEx(DWORD_PTR pid, LPCTSTR fileResult)
{
    ProcessLister::setDebugPrivileges();
    auto procList = Scylla::processLister.getProcessListSnapshotNative();

    Process process{};
    for (auto& procit : procList)
    {
        if (procit.PID == pid)
        {
            process = procit;
            break;
        }
    }

    SCY_HANDLE hScyllaContext;

    if (!InitContext(&hScyllaContext, process.PID))
        return ERROR_DLL_INIT_FAILED;

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
    ProcessAccessHelp::selectedModule = nullptr;

    ProcessAccessHelp::targetImageBase = process.imageBase;
    ProcessAccessHelp::targetSizeOfImage = process.imageSize;

    process.imageSize = static_cast<DWORD>(ProcessAccessHelp::targetSizeOfImage);

    process.entryPoint = ProcessAccessHelp::getEntryPointFromFile(process.fullPath);

    Scylla::Log->log(TEXT("%s ImageBase 0x") PRINTF_DWORD_PTR_FULL TEXT(" ImageSize 0x%08X EntryPoint 0x") PRINTF_DWORD_PTR_FULL, process.filename, process.imageBase, process.imageSize, process.entryPoint + process.imageBase);

    PeParser peFileD(process.imageBase, true);

    BOOL bDumpResult = false;
    if (peFileD.isValidPeFile())
    {
        bDumpResult = peFileD.dumpProcess(process.imageBase, process.entryPoint + process.imageBase, fileResult);
        if (bDumpResult)
        {
            const auto fileSize = static_cast<DWORD>(ProcessAccessHelp::getFileSize(fileResult));
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
                    const auto newSize = static_cast<DWORD>(ProcessAccessHelp::getFileSize(fileResult));

                    if (Scylla::config[UPDATE_HEADER_CHECKSUM].isTrue())
                    {
                        Scylla::Log->log(TEXT("Generating PE header checksum"));
                        if (!PeParser::updatePeHeaderChecksum(fileResult, newSize))
                        {
                            Scylla::Log->log(TEXT("Generating PE header checksum FAILED!"));
                        }
                    }

                    Scylla::Log->log(TEXT("Rebuild success %s"), fileResult);
                    Scylla::Log->log(TEXT("-> Old file size 0x%08X new file size 0x%08X (%d %%)"), fileSize, newSize, ((newSize * 100) / fileSize));
                }
                else
                {
                    Scylla::Log->log(TEXT("Rebuild failed, cannot save file %s"), fileResult);
                }
            }
        }
    }
    else
    {
        Scylla::Log->log(TEXT("Error: Invalid PE file or invalid PE header. Try reading PE header from disk/process."));
    }

    DeinitializeContext(hScyllaContext);
    if (bDumpResult)
        return ERROR_SUCCESS;
    else
        return ERROR_ACCESS_DENIED;
}

int IatFixAuto(SCY_HANDLE hScyllaContext, DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, LPCTSTR dumpFile, LPCTSTR iatFixFile)
{
    std::map<DWORD_PTR, ImportModuleThunk> moduleList;

    auto* pPrivScyContext = reinterpret_cast<SCY_CONTEXT_T*>(hScyllaContext);

    if (!pPrivScyContext)
        return SCY_ERROR_PIDNOTFOUND;


    //ProcessAccessHelp::closeProcessHandle();
    //apiReader.clearAll();

    //if (!ProcessAccessHelp::openProcessHandle(processPtr->PID))
    //{
    //	return SCY_ERROR_PROCOPEN;
    //}

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
    ProcessAccessHelp::selectedModule = nullptr;

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

int IatSearch(SCY_HANDLE hScyllaContext, DWORD_PTR * iatStart, size_t *iatSize, DWORD_PTR searchStart, BOOL advancedSearch)
{
    return Scylla::iat_search(hScyllaContext, iatStart, iatSize, searchStart, advancedSearch);
}

BOOL InitContext(PSCY_HANDLE phCtxt, DWORD_PTR TargetProcessPid)
{
    return Scylla::initialize_context(phCtxt, TargetProcessPid);
}

BOOL DeinitializeContext(SCY_HANDLE hCtxt)
{
    return Scylla::deinitialize_context(hCtxt);
}
