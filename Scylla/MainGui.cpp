#include "MainGui.h"
#include <cinttypes>
#include <VersionHelpers.h>

#include "Architecture.h"
//#include "PluginLoader.h"
//#include "ConfigurationHolder.h"
#include "PeParser.h"
#include "DllInjectionPlugin.h"
#include "DisassemblerGui.h"
#include "PickApiGui.h"
//#include "NativeWinApi.h"
#include "ImportRebuilder.h"
#include "Scylla.h"
#include "AboutGui.h"
#include "DonateGui.h"
#include "OptionsGui.h"
#include "TreeImportExport.h"
#include "ListboxLog.h"

// Globals
CAppModule _Module;

const TCHAR MainGui::filterExe[] = TEXT("Executable (*.exe)\0*.exe\0All files\0*.*\0");
const TCHAR MainGui::filterDll[] = TEXT("Dynamic Link Library (*.dll)\0*.dll\0All files\0*.*\0");
const TCHAR MainGui::filterExeDll[] = TEXT("Executable (*.exe)\0*.exe\0Dynamic Link Library (*.dll)\0*.dll\0All files\0*.*\0");
const TCHAR MainGui::filterTxt[] = TEXT("Text file (*.txt)\0*.txt\0All files\0*.*\0");
const TCHAR MainGui::filterXml[] = TEXT("XML file (*.xml)\0*.xml\0All files\0*.*\0");
const TCHAR MainGui::filterMem[] = TEXT("MEM file (*.mem)\0*.mem\0All files\0*.*\0");

ListboxLog logger;

int InitializeGui(HINSTANCE hInstance, LPARAM param)
{
    CoInitialize(nullptr);

    AtlInitCommonControls(ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES);

    Scylla::initialize(&logger, true);

    HRESULT hRes = _Module.Init(nullptr, hInstance);
    ATLASSERT(SUCCEEDED(hRes));

    const int nRet = 0;
    // BLOCK: Run application
    {
        MainGui dlgMain;
        //MainGui* pMainGui = &dlgMain; // o_O

        CMessageLoop loop;
        _Module.AddMessageLoop(&loop);

        dlgMain.Create(GetDesktopWindow(), param);

        dlgMain.ShowWindow(SW_SHOW);

        loop.Run();
    }

    _Module.Term();
    CoUninitialize();

    return nRet;
}

MainGui::MainGui()
    : m_bMsgHandled(false)
    , stringBuffer{}
    , importsHandling(TreeImports)
    , selectedProcess(nullptr)
    , isProcessSuspended(false)
    , hProcessContext(NULL)
    , TreeImportsSubclass(this, IDC_TREE_IMPORTS)
{
    /*
    Logger::getDebugLogFilePath();
    ConfigurationHolder::loadConfiguration();
    PluginLoader::findAllPlugins();
    NativeWinApi::initialize();
    SystemInformation::getSystemInformation();

    if(ConfigurationHolder::getConfigObject(DEBUG_PRIVILEGE)->isTrue())
    {
        processLister.setDebugPrivileges();
    }


    ProcessAccessHelp::getProcessModules(GetCurrentProcessId(), ProcessAccessHelp::ownModuleList);
    */

    hIcon.LoadIcon(IDI_ICON_SCYLLA);
    hMenuImports.LoadMenu(IDR_MENU_IMPORTS);
    hMenuLog.LoadMenu(IDR_MENU_LOG);
    accelerators.LoadAccelerators(IDR_ACCELERATOR_MAIN);

    hIconCheck.LoadIcon(IDI_ICON_CHECK, 16, 16);
    hIconWarning.LoadIcon(IDI_ICON_WARNING, 16, 16);
    hIconError.LoadIcon(IDI_ICON_ERROR, 16, 16);
}

MainGui::~MainGui()
{
    Scylla::deinitialize_context(hProcessContext);
}

BOOL MainGui::PreTranslateMessage(MSG* pMsg)
{
    if (accelerators.TranslateAccelerator(m_hWnd, pMsg))
    {
        return TRUE; // handled keyboard shortcuts
    }
    else if (IsDialogMessage(pMsg))
    {
        return TRUE; // handled dialog messages
    }

    return FALSE;
}

void MainGui::InitDllStartWithPreSelect(PGUI_DLL_PARAMETER guiParam)
{
    TCHAR TmpStringBuffer[600] = { 0 };

    ComboProcessList.ResetContent();
    std::vector<Process>& processList = Scylla::processLister.getProcessListSnapshotNative();
    int newSel = -1;
    for (size_t i = 0; i < processList.size(); i++)
    {
        if (processList[i].PID == guiParam->dwProcessId)
            newSel = static_cast<int>(i);
        _stprintf_s(TmpStringBuffer, TEXT("%zu - %s - %s"), processList[i].PID, processList[i].filename, processList[i].fullPath);
        ComboProcessList.AddString(TmpStringBuffer);
    }
    if (newSel != -1)
    {
        ComboProcessList.SetCurSel(newSel);
        processSelectedActionHandler(newSel);

        if (guiParam->mod) //init mod
        {
            //select DLL
            const size_t len = ProcessAccessHelp::moduleList.size();
            newSel = -1;
            for (size_t i = 0; i < len; i++)
            {
                if (ProcessAccessHelp::moduleList.at(i).modBaseAddr == reinterpret_cast<DWORD_PTR>(guiParam->mod))
                {
                    newSel = static_cast<int>(i);
                    break;
                }
            }
            if (newSel != -1)
            {
                //get selected module
                ProcessAccessHelp::selectedModule = &ProcessAccessHelp::moduleList.at(newSel);

                ProcessAccessHelp::targetImageBase = ProcessAccessHelp::selectedModule->modBaseAddr;
                ProcessAccessHelp::targetSizeOfImage = ProcessAccessHelp::selectedModule->modBaseSize;

                const DWORD modEntryPoint = ProcessAccessHelp::getEntryPointFromFile(ProcessAccessHelp::selectedModule->fullPath);

                EditOEPAddress.SetValue(modEntryPoint + ProcessAccessHelp::targetImageBase);

                Scylla::Log->log(TEXT("->>> Module %s selected."), ProcessAccessHelp::selectedModule->getFilename());
                Scylla::Log->log(TEXT("Imagebase: ") PRINTF_DWORD_PTR_FULL TEXT(" Size: %08X EntryPoint: %08X"), ProcessAccessHelp::selectedModule->modBaseAddr, ProcessAccessHelp::selectedModule->modBaseSize, modEntryPoint);
            }
        }
    }
    if (guiParam->entrypoint)
        EditOEPAddress.SetValue(guiParam->entrypoint);
}

BOOL MainGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
    if (!IsWindowsXPOrGreater())
    {
        if (IDCANCEL == MessageBox(TEXT("Operating System is not supported\r\nContinue anyway?"), TEXT("Scylla"), MB_ICONWARNING | MB_OKCANCEL))
        {
            SendMessage(WM_CLOSE);
            return FALSE;
        }
    }

    // register ourselves to receive PreTranslateMessage
    CMessageLoop* pLoop = _Module.GetMessageLoop();
    pLoop->AddMessageFilter(this);

    setupStatusBar();

    DoDataExchange(); // attach controls
    DlgResize_Init(true, true); // init CDialogResize

    logger.setWindow(ListLog);

    appendPluginListToMenu(hMenuImports.GetSubMenu(0));
    appendPluginListToMenu(CMenuHandle(GetMenu()).GetSubMenu(MenuImportsOffsetTrace));

    enableDialogControls(FALSE);
    setIconAndDialogCaption();

    if (lInitParam)
    {
        InitDllStartWithPreSelect(reinterpret_cast<PGUI_DLL_PARAMETER>(lInitParam));
    }
    return TRUE;
}


void MainGui::OnDestroy()
{
    PostQuitMessage(0);
}

void MainGui::OnSize(UINT nType, CSize size)
{
    StatusBar.SendMessage(WM_SIZE);
    SetMsgHandled(FALSE);
}

void MainGui::OnContextMenu(CWindow wnd, CPoint point)
{
    switch (wnd.GetDlgCtrlID())
    {
    case IDC_TREE_IMPORTS:
        DisplayContextMenuImports(wnd, point);
        return;
    case IDC_LIST_LOG:
        DisplayContextMenuLog(wnd, point);
        return;
    default: ;
    }

    SetMsgHandled(FALSE);
}

void MainGui::OnCommand(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    // Handle plugin trace menu selection
    if (uNotifyCode == 0 && !wndCtl.IsWindow()) // make sure it's a menu
    {
        if ((nID >= PLUGIN_MENU_BASE_ID) && (nID <= static_cast<int>(Scylla::plugins.getScyllaPluginList().size() + Scylla::plugins.getImprecPluginList().size() +
            PLUGIN_MENU_BASE_ID)))
        {
            pluginActionHandler(nID);
            return;
        }
    }
    SetMsgHandled(FALSE);
}

LRESULT MainGui::OnTreeImportsDoubleClick(const NMHDR* pnmh)
{
    if (TreeImports.GetCount() < 1)
        return 0;

    // Get item under cursor
    CTreeItem over = findTreeItem(CPoint(GetMessagePos()), true);
    if (over && importsHandling.isImport(over))
    {
        pickApiActionHandler(over);
    }

    return 0;
}

LRESULT MainGui::OnTreeImportsKeyDown(const NMHDR* pnmh)
{
    const auto tkd = reinterpret_cast<const NMTVKEYDOWN *>(pnmh);
    switch (tkd->wVKey)
    {
    case VK_RETURN:
    {
        CTreeItem selected = TreeImports.GetFocusItem();
        if (!selected.IsNull() && importsHandling.isImport(selected))
        {
            pickApiActionHandler(selected);
        }
        return 1;
    }
    case VK_DELETE:
        deleteSelectedImportsActionHandler();
        return 1;
    default: ;
    }

    SetMsgHandled(FALSE);
    return 0;
}

UINT MainGui::OnTreeImportsSubclassGetDlgCode(const MSG * lpMsg)
{
    if (lpMsg)
    {
        switch (lpMsg->wParam)
        {
        case VK_RETURN:
            return DLGC_WANTMESSAGE;
        default: ;
        }
    }

    SetMsgHandled(FALSE);
    return 0;
}

void MainGui::OnTreeImportsSubclassChar(UINT nChar, UINT nRepCnt, UINT nFlags)
{
    switch (nChar)
    {
    case VK_RETURN:
        break;
    default:
        SetMsgHandled(FALSE);
        break;
    }
}

void MainGui::OnProcessListDrop(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    fillProcessListComboBox(ComboProcessList);
}

void MainGui::OnProcessListSelected(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    const int index = ComboProcessList.GetCurSel();
    if (index != CB_ERR)
    {
        processSelectedActionHandler(index);
    }
}

void MainGui::OnPickDLL(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    pickDllActionHandler();
}

void MainGui::OnOptions(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    optionsActionHandler();
}

void MainGui::OnDump(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    dumpActionHandler();
}

void MainGui::OnDumpMemory(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    dumpMemoryActionHandler();
}

void MainGui::OnDumpSection(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    dumpSectionActionHandler();
}

void MainGui::OnFixDump(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    dumpFixActionHandler();
}

void MainGui::OnPERebuild(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    peRebuildActionHandler();
}

void MainGui::OnDLLInject(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    dllInjectActionHandler();
}
void MainGui::OnDisassembler(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    disassemblerActionHandler();
}

void MainGui::OnIATAutoSearch(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    iatAutosearchActionHandler();
}

void MainGui::OnGetImports(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    getImportsActionHandler();
}

void MainGui::OnInvalidImports(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    showInvalidImportsActionHandler();
}

void MainGui::OnSuspectImports(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    showSuspectImportsActionHandler();
}

void MainGui::OnClearImports(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    clearImportsActionHandler();
}

void MainGui::OnInvalidateSelected(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    invalidateSelectedImportsActionHandler();
}

void MainGui::OnCutSelected(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    deleteSelectedImportsActionHandler();
}

void MainGui::OnSaveTree(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    saveTreeActionHandler();
}

void MainGui::OnLoadTree(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    loadTreeActionHandler();
}

void MainGui::OnAutotrace(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    // TODO
}

void MainGui::OnExit(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    if (isProcessSuspended)
    {
        const int msgboxID = MessageBox(TEXT("Process is suspended. Do you want to terminate the process?\r\n\r\nYES = Terminate Process\r\nNO = Try to resume the process\r\nCancel = Do nothing"), TEXT("Information"), MB_YESNOCANCEL | MB_ICONINFORMATION);

        switch (msgboxID)
        {
        case IDYES:
            ProcessAccessHelp::terminateProcess();
            break;
        case IDNO:
            ProcessAccessHelp::resumeProcess();
            break;
        default:
            break;
        }
    }

    DestroyWindow();
}

void MainGui::OnAbout(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    showAboutDialog();
}

void MainGui::OnDonate(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    showDonateDialog();
}

void MainGui::setupStatusBar()
{
    StatusBar.Create(m_hWnd, nullptr, TEXT(""), WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | SBARS_TOOLTIPS, NULL, IDC_STATUS_BAR);

    CRect rcMain, rcStatus;
    GetClientRect(&rcMain);
    StatusBar.GetWindowRect(&rcStatus);

    const int PARTS = 4;
    int widths[PARTS];

    widths[PART_COUNT] = rcMain.Width() / 5;
    widths[PART_INVALID] = widths[PART_COUNT] + rcMain.Width() / 5;
    widths[PART_IMAGEBASE] = widths[PART_INVALID] + rcMain.Width() / 3;
    widths[PART_MODULE] = -1;

    StatusBar.SetParts(PARTS, widths);

    ResizeClient(rcMain.Width(), rcMain.Height() + rcStatus.Height(), FALSE);
}

void MainGui::updateStatusBar()
{
    // Rewrite ImportsHandling so we get these easily
    const unsigned int totalImports = importsHandling.thunkCount();
    const unsigned int invalidImports = importsHandling.invalidThunkCount();

    // \t = center, \t\t = right-align
    _stprintf_s(stringBuffer, TEXT("\tImports: %u"), totalImports);
    StatusBar.SetText(PART_COUNT, stringBuffer);

    if (invalidImports > 0)
    {
        StatusBar.SetIcon(PART_INVALID, hIconError);
    }
    else
    {
        StatusBar.SetIcon(PART_INVALID, hIconCheck);
    }

    _stprintf_s(stringBuffer, TEXT("\tInvalid: %u"), invalidImports);
    StatusBar.SetText(PART_INVALID, stringBuffer);

    if (selectedProcess)
    {
        DWORD_PTR imageBase;
        LPCTSTR fileName;

        if (ProcessAccessHelp::selectedModule)
        {
            imageBase = ProcessAccessHelp::selectedModule->modBaseAddr;
            fileName = ProcessAccessHelp::selectedModule->getFilename();
        }
        else
        {
            imageBase = selectedProcess->imageBase;
            fileName = selectedProcess->filename;
        }

        _stprintf_s(stringBuffer, TEXT("\tImagebase: ") PRINTF_DWORD_PTR_FULL, imageBase);
        StatusBar.SetText(PART_IMAGEBASE, stringBuffer);
        StatusBar.SetText(PART_MODULE, fileName);
        StatusBar.SetTipText(PART_MODULE, fileName);
    }
    else
    {
        StatusBar.SetText(PART_IMAGEBASE, TEXT(""));
        StatusBar.SetText(PART_MODULE, TEXT(""));
    }
}

bool MainGui::showFileDialog(LPTSTR selectedFile, bool save, LPCTSTR defFileName, LPCTSTR filter, LPCTSTR defExtension, LPCTSTR directory) const
{
    OPENFILENAME ofn{};

    // WTL doesn't support new explorer styles on Vista and up
    // This is because it uses a custom hook, we could remove it or derive
    // from CFileDialog but this solution is easier and allows more control anyway (e.g. initial dir)

    if (defFileName)
    {
        _tcscpy_s(selectedFile, MAX_PATH, defFileName);
    }
    else
    {
        selectedFile[0] = L'\0';
    }

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hWnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrDefExt = defExtension; // only first 3 chars are used, no dots!
    ofn.lpstrFile = selectedFile;
    ofn.lpstrInitialDir = directory;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;

    /*
     *OFN_EXPLORER is automatically used, it only has to be specified
     *if using a custom hook
     *OFN_LONGNAMES is automatically used by explorer-style dialogs
     */

    if (save)
        ofn.Flags |= OFN_OVERWRITEPROMPT;
    else
        ofn.Flags |= OFN_FILEMUSTEXIST;

    if (save)
        return 0 != GetSaveFileName(&ofn);
    else
        return 0 != GetOpenFileName(&ofn);
}

void MainGui::setIconAndDialogCaption()
{
    SetIcon(hIcon, TRUE);
    SetIcon(hIcon, FALSE);

    SetWindowText(APPNAME TEXT(" ") ARCHITECTURE TEXT(" ") APPVERSION);
}

void MainGui::pickDllActionHandler()
{
    if (!selectedProcess)
        return;

    PickDllGui dlgPickDll(ProcessAccessHelp::moduleList);
    if (dlgPickDll.DoModal())
    {
        //get selected module
        ProcessAccessHelp::selectedModule = dlgPickDll.getSelectedModule();

        ProcessAccessHelp::targetImageBase = ProcessAccessHelp::selectedModule->modBaseAddr;
        ProcessAccessHelp::targetSizeOfImage = ProcessAccessHelp::selectedModule->modBaseSize;

        const DWORD modEntryPoint = ProcessAccessHelp::getEntryPointFromFile(ProcessAccessHelp::selectedModule->fullPath);

        EditOEPAddress.SetValue(modEntryPoint + ProcessAccessHelp::targetImageBase);

        Scylla::Log->log(TEXT("->>> Module %s selected."), ProcessAccessHelp::selectedModule->getFilename());
        Scylla::Log->log(TEXT("Imagebase: ") PRINTF_DWORD_PTR_FULL TEXT(" Size: %08X EntryPoint: %08X"), ProcessAccessHelp::selectedModule->modBaseAddr, ProcessAccessHelp::selectedModule->modBaseSize, modEntryPoint);
    }
    else
    {
        ProcessAccessHelp::selectedModule = nullptr;
    }

    updateStatusBar();
}

void MainGui::pickApiActionHandler(const CTreeItem& item)
{
    if (!importsHandling.isImport(item))
        return;

    // TODO: new node when user picked an API from another DLL?

    PickApiGui dlgPickApi(ProcessAccessHelp::moduleList);
    if (dlgPickApi.DoModal())
    {
        const ApiInfo* api = dlgPickApi.getSelectedApi();
        if (api && api->module)
        {
            importsHandling.setImport(item, api->module->getFilename(), api->name, api->ordinal, api->hint, true, api->isForwarded);
        }
    }

    updateStatusBar();
}

void MainGui::startDisassemblerGui(const CTreeItem& selectedTreeNode)
{
    if (!selectedProcess)
        return;

    const DWORD_PTR address = importsHandling.getApiAddressByNode(selectedTreeNode);
    if (address)
    {
        BYTE test;
        if (!ProcessAccessHelp::readMemoryFromProcess(address, sizeof(test), &test))
        {
            _stprintf_s(stringBuffer, TEXT("Can't read memory at ") PRINTF_DWORD_PTR_FULL, address);
            MessageBox(stringBuffer, TEXT("Failure"), MB_ICONERROR);
        }
        else
        {
            DisassemblerGui dlgDisassembler(address, &apiReader);
            dlgDisassembler.DoModal();
        }
    }
}

void MainGui::processSelectedActionHandler(int index)
{
    std::vector<Process>& processList = Scylla::processLister.getProcessList();
    Process &process = processList.at(index);
    selectedProcess = nullptr;

    // Cleanup previous results
    clearImportsActionHandler();
    Scylla::deinitialize_context(hProcessContext);

    Scylla::Log->log(TEXT("Analyzing %s"), process.fullPath);

    // Open Scylla handle on current process
    if (!Scylla::initialize_context(&hProcessContext, process.PID))
    {
        enableDialogControls(FALSE);
        Scylla::Log->log(TEXT("Error: Cannot open process handle."));
        updateStatusBar();
        return;
    }

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

    apiReader.readApisFromModuleList();

    Scylla::Log->log(TEXT("Loading modules done."));

    //TODO improve
    ProcessAccessHelp::selectedModule = nullptr;

    ProcessAccessHelp::targetImageBase = process.imageBase;
    ProcessAccessHelp::targetSizeOfImage = process.imageSize;

    process.imageSize = static_cast<DWORD>(ProcessAccessHelp::targetSizeOfImage);


    Scylla::Log->log(TEXT("Imagebase: ") PRINTF_DWORD_PTR_FULL TEXT(" Size: %08X"), process.imageBase, process.imageSize);

    process.entryPoint = ProcessAccessHelp::getEntryPointFromFile(process.fullPath);

    EditOEPAddress.SetValue(process.entryPoint + process.imageBase);

    selectedProcess = &process;
    enableDialogControls(TRUE);

    updateStatusBar();
}

void MainGui::fillProcessListComboBox(CComboBox& hCombo)
{
    TCHAR TmpStringBuffer[600] = { 0 };
    hCombo.ResetContent();


    std::vector<Process>& processList = Scylla::processLister.getProcessListSnapshotNative();

    for (size_t i = 0; i < processList.size(); i++)
    {
        _stprintf_s(TmpStringBuffer, TEXT("%zu - %s - %s"), processList[i].PID, processList[i].filename, processList[i].fullPath);
        hCombo.AddString(TmpStringBuffer);
    }
}

/*
void MainGui::addTextToOutputLog(const WCHAR * text)
{
    if (m_hWnd)
    {
        ListLog.SetCurSel(ListLog.AddString(text));
    }
}
*/

void MainGui::clearOutputLog()
{
    if (m_hWnd)
    {
        ListLog.ResetContent();
    }
}

bool MainGui::saveLogToFile(LPCTSTR file) const
{
    const BYTE BOM[] = { 0xFF, 0xFE }; // UTF-16 little-endian
    const TCHAR newLine[] = TEXT("\r\n");
    bool success = true;

    const auto hFile = CreateFile(file, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        ProcessAccessHelp::writeMemoryToFileEnd(hFile, sizeof(BOM), BOM);

        TCHAR * buffer = nullptr;
        size_t bufsize = 0;
        for (int i = 0; i < ListLog.GetCount(); i++)
        {
            size_t size = ListLog.GetTextLen(i);
            size += _countof(newLine) - 1;
            if (size + 1 > bufsize)
            {
                bufsize = size + 1;
                delete[] buffer;
                try
                {
                    buffer = new TCHAR[bufsize];
                }
                catch (std::bad_alloc&)
                {
                    buffer = nullptr;
                    success = false;
                    break;
                }
            }

            ListLog.GetText(i, buffer);
            _tcscat_s(buffer, bufsize, newLine);

            ProcessAccessHelp::writeMemoryToFileEnd(hFile, size * sizeof(TCHAR), buffer);
        }
        delete[] buffer;
        CloseHandle(hFile);
    }
    return success;
}

void MainGui::showInvalidImportsActionHandler()
{
    importsHandling.selectImports(true, false);
    GotoDlgCtrl(TreeImports);
}

void MainGui::showSuspectImportsActionHandler()
{
    importsHandling.selectImports(false, true);
    GotoDlgCtrl(TreeImports);
}

void MainGui::deleteSelectedImportsActionHandler()
{
    CTreeItem selected = TreeImports.GetFirstSelectedItem();
    while (!selected.IsNull())
    {
        if (importsHandling.isModule(selected))
        {
            importsHandling.cutModule(selected);
        }
        else
        {
            importsHandling.cutImport(selected);
        }
        selected = TreeImports.GetNextSelectedItem(selected);
    }
    updateStatusBar();
}

void MainGui::invalidateSelectedImportsActionHandler()
{
    CTreeItem selected = TreeImports.GetFirstSelectedItem();
    while (!selected.IsNull())
    {
        if (importsHandling.isImport(selected))
        {
            importsHandling.invalidateImport(selected);
        }
        selected = TreeImports.GetNextSelectedItem(selected);
    }
    updateStatusBar();
}

void MainGui::loadTreeActionHandler()
{
    if (!selectedProcess)
        return;

    TCHAR selectedFilePath[MAX_PATH];
    getCurrentModulePath(stringBuffer, _countof(stringBuffer));
    if (showFileDialog(selectedFilePath, false, nullptr, filterXml, nullptr, stringBuffer))
    {
        TreeImportExport treeIO(selectedFilePath);
        DWORD_PTR addrOEP = 0;
        DWORD_PTR addrIAT = 0;
        DWORD sizeIAT = 0;

        if (!treeIO.importTreeList(importsHandling.moduleList, &addrOEP, &addrIAT, &sizeIAT))
        {
            Scylla::Log->log(TEXT("Loading tree file failed %s"), selectedFilePath);
            MessageBox(TEXT("Loading tree file failed."), TEXT("Failure"), MB_ICONERROR);
        }
        else
        {
            EditOEPAddress.SetValue(addrOEP);
            EditIATAddress.SetValue(addrIAT);
            EditIATSize.SetValue(sizeIAT);

            importsHandling.displayAllImports();
            updateStatusBar();

            Scylla::Log->log(TEXT("Loaded tree file %s"), selectedFilePath);
            Scylla::Log->log(TEXT("-> OEP: ") PRINTF_DWORD_PTR_FULL, addrOEP);
            Scylla::Log->log(TEXT("-> IAT: ") PRINTF_DWORD_PTR_FULL TEXT(" Size: ") PRINTF_DWORD_PTR, addrIAT, sizeIAT);
        }
    }
}

void MainGui::saveTreeActionHandler()
{
    if (!selectedProcess)
        return;

    TCHAR selectedFilePath[MAX_PATH];
    getCurrentModulePath(stringBuffer, _countof(stringBuffer));
    if (showFileDialog(selectedFilePath, true, nullptr, filterXml, TEXT("xml"), stringBuffer))
    {
        TreeImportExport treeIO(selectedFilePath);
        const DWORD_PTR addrOEP = EditOEPAddress.GetValue();
        const DWORD_PTR addrIAT = EditIATAddress.GetValue();
        const DWORD sizeIAT = EditIATSize.GetValue();

        if (!treeIO.exportTreeList(importsHandling.moduleList, selectedProcess, addrOEP, addrIAT, sizeIAT))
        {
            Scylla::Log->log(TEXT("Saving tree file failed %s"), selectedFilePath);
            MessageBox(TEXT("Saving tree file failed."), TEXT("Failure"), MB_ICONERROR);
        }
        else
        {
            Scylla::Log->log(TEXT("Saved tree file %s"), selectedFilePath);
        }
    }
}

void MainGui::iatAutosearchActionHandler()
{
    DWORD_PTR addressIAT = 0;
    DWORD_PTR addressIATAdv = 0;
    size_t sizeIAT = 0, sizeIATAdv = 0;

    if (!selectedProcess)
        return;

    if (EditOEPAddress.GetWindowTextLength() == 0)
        return;

    const DWORD_PTR searchAddress = EditOEPAddress.GetValue();
    if (!searchAddress)
        return;


    // Normal search
    if (SCY_ERROR_SUCCESS == Scylla::iat_search(hProcessContext, &addressIAT, &sizeIAT, searchAddress, false))
    {
        Scylla::Log->log(TEXT("IAT Search Nor: IAT VA ") PRINTF_DWORD_PTR_FULL TEXT(" RVA ") PRINTF_DWORD_PTR_FULL TEXT(" Size 0x%04X (%d)"), addressIAT, addressIAT - ProcessAccessHelp::targetImageBase, sizeIAT, sizeIAT);
    }
    else
    {
        Scylla::Log->log(TEXT("IAT Search Nor: IAT not found at OEP ") PRINTF_DWORD_PTR_FULL TEXT("!"), searchAddress);
    }

    // optional advanced search
    const bool bAdvancedSearch = Scylla::config[USE_ADVANCED_IAT_SEARCH].isTrue();
    if (bAdvancedSearch)
    {
        if (SCY_ERROR_SUCCESS == Scylla::iat_search(hProcessContext, &addressIATAdv, &sizeIATAdv, searchAddress, true))
        {
            Scylla::Log->log(TEXT("IAT Search Adv: IAT VA ") PRINTF_DWORD_PTR_FULL TEXT(" RVA ") PRINTF_DWORD_PTR_FULL TEXT(" Size 0x%04X (%d)"), addressIATAdv, addressIATAdv - ProcessAccessHelp::targetImageBase, sizeIATAdv, sizeIATAdv);
        }
        else
        {
            Scylla::Log->log(TEXT("IAT Search Adv: IAT not found at OEP ") PRINTF_DWORD_PTR_FULL TEXT("!"), searchAddress);
        }
    }

    // Executive arbitrage between normal and advanced search results
    if (addressIAT != 0 && addressIATAdv == 0)
    {
        setDialogIATAddressAndSize(addressIAT, sizeIAT);
    }
    else if (addressIAT == 0 && addressIATAdv != 0)
    {
        setDialogIATAddressAndSize(addressIATAdv, sizeIATAdv);
    }
    else if (addressIAT != 0 && addressIATAdv != 0)
    {
        if (addressIATAdv != addressIAT || sizeIAT != sizeIATAdv)
        {
            const int msgboxID = MessageBox(TEXT("Result of advanced and normal search is different. Do you want to use the IAT Search Advanced result?"), TEXT("Information"), MB_YESNO | MB_ICONINFORMATION);
            if (msgboxID == IDYES)
            {
                setDialogIATAddressAndSize(addressIATAdv, sizeIATAdv);
            }
            else
            {
                setDialogIATAddressAndSize(addressIAT, sizeIAT);
            }
        }
        else
        {
            setDialogIATAddressAndSize(addressIAT, sizeIAT);
        }
    }

}

void MainGui::getImportsActionHandler()
{
    if (!selectedProcess)
        return;

    const DWORD_PTR addressIAT = EditIATAddress.GetValue();
    const DWORD sizeIAT = EditIATSize.GetValue();

    if (addressIAT && sizeIAT)
    {
        apiReader.readAndParseIAT(addressIAT, sizeIAT, importsHandling.moduleList);
        importsHandling.scanAndFixModuleList();
        importsHandling.displayAllImports();

        updateStatusBar();

        if (Scylla::config[SCAN_DIRECT_IMPORTS].isTrue())
        {
            iatReferenceScan.ScanForDirectImports = true;
            iatReferenceScan.ScanForNormalImports = false;
            iatReferenceScan.apiReader = &apiReader;
            iatReferenceScan.startScan(ProcessAccessHelp::targetImageBase, static_cast<DWORD>(ProcessAccessHelp::targetSizeOfImage), addressIAT, sizeIAT);

            Scylla::Log->log(TEXT("DIRECT IMPORTS - Found %d possible direct imports with %d unique APIs!"), iatReferenceScan.numberOfFoundDirectImports(), iatReferenceScan.numberOfFoundUniqueDirectImports());

            if (iatReferenceScan.numberOfFoundDirectImports() > 0)
            {
                if (iatReferenceScan.numberOfDirectImportApisNotInIat() > 0)
                {
                    Scylla::Log->log(TEXT("DIRECT IMPORTS - Found %d additional api addresses!"), iatReferenceScan.numberOfDirectImportApisNotInIat());
                    const DWORD sizeIatNew = iatReferenceScan.addAdditionalApisToList();
                    Scylla::Log->log(TEXT("DIRECT IMPORTS - Old IAT size 0x%08X new IAT size 0x%08X!"), sizeIAT, sizeIatNew);
                    EditIATSize.SetValue(sizeIatNew);
                    importsHandling.scanAndFixModuleList();
                    importsHandling.displayAllImports();
                }

                iatReferenceScan.printDirectImportLog();

                if (Scylla::config[FIX_DIRECT_IMPORTS_NORMAL].isTrue() && (!Scylla::config[FIX_DIRECT_IMPORTS_UNIVERSAL]
                    .isTrue()))
                {
                    const int msgboxID = MessageBox(TEXT("Direct Imports found. I can patch only direct imports by JMP/CALL (use universal method if you don't like this) but where is the junk byte?\r\n\r\nYES = After Instruction\r\nNO = Before the Instruction\r\nCancel = Do nothing"), TEXT("Information"), MB_YESNOCANCEL | MB_ICONINFORMATION);

                    if (msgboxID != IDCANCEL)
                    {
                        const bool isAfter = msgboxID == IDYES;

                        iatReferenceScan.patchDirectImportsMemory(isAfter);
                        Scylla::Log->log(TEXT("DIRECT IMPORTS - Patched! Please dump target."));
                    }

                }
            }

        }


        if (isIATOutsidePeImage(addressIAT))
        {
            Scylla::Log->log(TEXT("WARNING! IAT is not inside the PE image, requires rebasing!"));
        }
    }
}

void MainGui::SetupImportsMenuItems(const CTreeItem& item)
{
    bool isImport = false;
    const bool isItem = !item.IsNull();
    if (isItem)
    {
        isImport = importsHandling.isImport(item);
    }

    CMenuHandle hSub = hMenuImports.GetSubMenu(0);

    const UINT itemOnly = isItem ? MF_ENABLED : MF_GRAYED;
    const UINT importOnly = isImport ? MF_ENABLED : MF_GRAYED;

    hSub.EnableMenuItem(ID__INVALIDATE, itemOnly);
    hSub.EnableMenuItem(ID__DISASSEMBLE, importOnly);
    hSub.EnableMenuItem(ID__CUTTHUNK, importOnly);

    hSub.EnableMenuItem(ID__DELETETREENODE, itemOnly);
}

void MainGui::DisplayContextMenuImports(CWindow hwnd, CPoint pt)
{
    if (TreeImports.GetCount() < 1)
        return;

    CTreeItem over;

    if (pt.x == -1 && pt.y == -1) // invoked by keyboard
    {
        CRect pos;
        over = TreeImports.GetFocusItem();
        if (over)
        {
            over.EnsureVisible();
            over.GetRect(&pos, TRUE);
            TreeImports.ClientToScreen(&pos);
        }
        else
        {
            TreeImports.GetWindowRect(&pos);
        }
        pt = pos.TopLeft();
    }
    else
    {
        // Get item under cursor
        over = findTreeItem(pt, true);
    }

    SetupImportsMenuItems(over);

    CMenuHandle hSub = hMenuImports.GetSubMenu(0);
    BOOL menuItem = hSub.TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, hwnd);
    if (menuItem)
    {
        if ((menuItem >= PLUGIN_MENU_BASE_ID) && (menuItem <= static_cast<int>(Scylla::plugins.getScyllaPluginList().size() + Scylla::plugins.getImprecPluginList().size() +
            PLUGIN_MENU_BASE_ID)))
        {
            //wsprintf(stringBuffer, L"%d %s\n",menuItem,pluginList[menuItem - PLUGIN_MENU_BASE_ID].pluginName);
            //MessageBox(stringBuffer, L"plugin selection");

            pluginActionHandler(menuItem);
            return;
        }
        switch (menuItem)
        {
        case ID__INVALIDATE:
            if (importsHandling.isModule(over))
                importsHandling.invalidateModule(over);
            else
                importsHandling.invalidateImport(over);
            break;
        case ID__DISASSEMBLE:
            startDisassemblerGui(over);
            break;
        case ID__EXPANDALLNODES:
            importsHandling.expandAllTreeNodes();
            break;
        case ID__COLLAPSEALLNODES:
            importsHandling.collapseAllTreeNodes();
            break;
        case ID__CUTTHUNK:
            importsHandling.cutImport(over);
            break;
        case ID__DELETETREENODE:
            importsHandling.cutModule(importsHandling.isImport(over) ? over.GetParent() : over);
            break;
        default: ;
        }
    }

    updateStatusBar();
}

void MainGui::DisplayContextMenuLog(CWindow hwnd, CPoint pt)
{
    if (pt.x == -1 && pt.y == -1) // invoked by keyboard
    {
        CRect pos;
        ListLog.GetWindowRect(&pos);
        pt = pos.TopLeft();
    }

    CMenuHandle hSub = hMenuLog.GetSubMenu(0);
    BOOL menuItem = hSub.TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, hwnd);
    if (menuItem)
    {
        switch (menuItem)
        {
        case ID__SAVE:
            TCHAR selectedFilePath[MAX_PATH];
            getCurrentModulePath(stringBuffer, _countof(stringBuffer));
            if (showFileDialog(selectedFilePath, true, nullptr, filterTxt, TEXT("txt"), stringBuffer))
            {
                saveLogToFile(selectedFilePath);
            }
            break;
        case ID__CLEAR:
            clearOutputLog();
            break;
        default: ;
        }
    }
}

void MainGui::appendPluginListToMenu(CMenuHandle hMenu)
{
    std::vector<Plugin> &scyllaPluginList = Scylla::plugins.getScyllaPluginList();
    std::vector<Plugin> &imprecPluginList = Scylla::plugins.getImprecPluginList();

    if (scyllaPluginList.size() > 0)
    {
        CMenuHandle newMenu;
        newMenu.CreatePopupMenu();

        for (size_t i = 0; i < scyllaPluginList.size(); i++)
        {
            newMenu.AppendMenu(MF_STRING, i + PLUGIN_MENU_BASE_ID, scyllaPluginList[i].pluginName);
        }

        hMenu.AppendMenu(MF_MENUBARBREAK);
        hMenu.AppendMenu(MF_POPUP, newMenu, TEXT("Scylla Plugins"));
    }

    if (imprecPluginList.size() > 0)
    {
        CMenuHandle newMenu;
        newMenu.CreatePopupMenu();

        for (size_t i = 0; i < imprecPluginList.size(); i++)
        {
            newMenu.AppendMenu(MF_STRING, scyllaPluginList.size() + i + PLUGIN_MENU_BASE_ID, imprecPluginList[i].pluginName);
        }

        hMenu.AppendMenu(MF_MENUBARBREAK);
        hMenu.AppendMenu(MF_POPUP, newMenu, TEXT("ImpREC Plugins"));
    }
}

void MainGui::dumpMemoryActionHandler()
{
    TCHAR selectedFilePath[MAX_PATH];
    DumpMemoryGui dlgDumpMemory;

    if (dlgDumpMemory.DoModal())
    {
        getCurrentModulePath(stringBuffer, _countof(stringBuffer));
        if (showFileDialog(selectedFilePath, true, dlgDumpMemory.dumpFilename, filterMem, TEXT("mem"), stringBuffer))
        {
            if (ProcessAccessHelp::writeMemoryToNewFile(selectedFilePath, dlgDumpMemory.dumpedMemorySize, dlgDumpMemory.dumpedMemory))
            {
                Scylla::Log->log(TEXT("Memory dump saved %s"), selectedFilePath);
            }
            else
            {
                Scylla::Log->log(TEXT("Error! Cannot write memory dump to disk"));
            }
        }
    }
}

void MainGui::dumpSectionActionHandler()
{
    TCHAR selectedFilePath[MAX_PATH] = { 0 };
    TCHAR defaultFilename[MAX_PATH] = { 0 };
    DumpSectionGui dlgDumpSection;
    LPCTSTR fileFilter;
    LPCTSTR defExtension;
    PeParser * peFile;

    dlgDumpSection.entryPoint = EditOEPAddress.GetValue();

    if (ProcessAccessHelp::selectedModule)
    {
        //dump DLL
        fileFilter = filterDll;
        defExtension = TEXT("dll");

        dlgDumpSection.imageBase = ProcessAccessHelp::selectedModule->modBaseAddr;
        //get it from gui
        _tcscpy_s(dlgDumpSection.fullpath, ProcessAccessHelp::selectedModule->fullPath);
    }
    else
    {
        fileFilter = filterExe;
        defExtension = TEXT("exe");

        dlgDumpSection.imageBase = ProcessAccessHelp::targetImageBase;
        //get it from gui
        _tcscpy_s(dlgDumpSection.fullpath, selectedProcess->fullPath);
    }

    if (dlgDumpSection.DoModal())
    {
        getCurrentDefaultDumpFilename(defaultFilename, _countof(defaultFilename));
        getCurrentModulePath(stringBuffer, _countof(stringBuffer));
        if (showFileDialog(selectedFilePath, true, defaultFilename, fileFilter, defExtension, stringBuffer))
        {
            checkSuspendProcess();

            if (Scylla::config[USE_PE_HEADER_FROM_DISK].isTrue())
            {
                peFile = new PeParser(dlgDumpSection.fullpath, true);
            }
            else
            {
                peFile = new PeParser(dlgDumpSection.imageBase, true);
            }

            std::vector<PeSection> & sectionList = dlgDumpSection.getSectionList();

            if (peFile->dumpProcess(dlgDumpSection.imageBase, dlgDumpSection.entryPoint, selectedFilePath, sectionList))
            {
                Scylla::Log->log(TEXT("Dump success %s"), selectedFilePath);
            }
            else
            {
                Scylla::Log->log(TEXT("Error: Cannot dump image."));
                MessageBox(TEXT("Cannot dump image."), TEXT("Failure"), MB_ICONERROR);
            }

            delete peFile;
        }
    }
}

void MainGui::dumpActionHandler()
{
    if (!selectedProcess)
        return;

    TCHAR selectedFilePath[MAX_PATH] = { 0 };
    TCHAR defaultFilename[MAX_PATH] = { 0 };
    LPCTSTR fileFilter;
    LPCTSTR defExtension;
    DWORD_PTR modBase;
    LPTSTR filename;
    PeParser * peFile;

    if (ProcessAccessHelp::selectedModule)
    {
        fileFilter = filterDll;
        defExtension = TEXT("dll");
    }
    else
    {
        fileFilter = filterExe;
        defExtension = TEXT("exe");
    }

    getCurrentModulePath(stringBuffer, _countof(stringBuffer));
    getCurrentDefaultDumpFilename(defaultFilename, _countof(defaultFilename));
    if (showFileDialog(selectedFilePath, true, defaultFilename, fileFilter, defExtension, stringBuffer))
    {
        const DWORD_PTR entrypoint = EditOEPAddress.GetValue();

        checkSuspendProcess();

        if (ProcessAccessHelp::selectedModule)
        {
            //dump DLL
            modBase = ProcessAccessHelp::selectedModule->modBaseAddr;
            filename = ProcessAccessHelp::selectedModule->fullPath;
        }
        else
        {
            //dump exe
            modBase = ProcessAccessHelp::targetImageBase;
            filename = selectedProcess->fullPath;
        }

        if (Scylla::config[USE_PE_HEADER_FROM_DISK].isTrue())
        {
            peFile = new PeParser(filename, true);
        }
        else
        {
            peFile = new PeParser(modBase, true);
        }

        if (peFile->isValidPeFile())
        {
            if (peFile->dumpProcess(modBase, entrypoint, selectedFilePath))
            {
                Scylla::Log->log(TEXT("Dump success %s"), selectedFilePath);
            }
            else
            {
                Scylla::Log->log(TEXT("Error: Cannot dump image."));
                MessageBox(TEXT("Cannot dump image."), TEXT("Failure"), MB_ICONERROR);
            }
        }
        else
        {
            Scylla::Log->log(TEXT("Error: Invalid PE file or invalid PE header. Try reading PE header from disk/process."));
        }

        delete peFile;
    }
}

void MainGui::peRebuildActionHandler()
{
    TCHAR selectedFilePath[MAX_PATH];

    getCurrentModulePath(stringBuffer, _countof(stringBuffer));
    if (showFileDialog(selectedFilePath, false, nullptr, filterExeDll, nullptr, stringBuffer))
    {
        if (Scylla::config[CREATE_BACKUP].isTrue())
        {
            if (!ProcessAccessHelp::createBackupFile(selectedFilePath))
            {
                Scylla::Log->log(TEXT("Creating backup file failed %s"), selectedFilePath);
            }
        }

        const auto fileSize = static_cast<DWORD>(ProcessAccessHelp::getFileSize(selectedFilePath));

        PeParser peFile(selectedFilePath, true);

        if (!peFile.isValidPeFile())
        {
            Scylla::Log->log(TEXT("This is not a valid PE file %s"), selectedFilePath);
            MessageBox(TEXT("Not a valid PE file."), TEXT("Failure"), MB_ICONERROR);
            return;
        }

        if (peFile.readPeSectionsFromFile())
        {
            peFile.setDefaultFileAlignment();

            if (Scylla::config[REMOVE_DOS_HEADER_STUB].isTrue())
            {
                peFile.removeDosStub();
            }

            peFile.alignAllSectionHeaders();
            peFile.fixPeHeader();

            if (peFile.savePeFileToDisk(selectedFilePath))
            {
                const auto newSize = static_cast<DWORD>(ProcessAccessHelp::getFileSize(selectedFilePath));

                if (Scylla::config[UPDATE_HEADER_CHECKSUM].isTrue())
                {
                    Scylla::Log->log(TEXT("Generating PE header checksum"));
                    if (!PeParser::updatePeHeaderChecksum(selectedFilePath, newSize))
                    {
                        Scylla::Log->log(TEXT("Generating PE header checksum FAILED!"));
                    }
                }

                Scylla::Log->log(TEXT("Rebuild success %s"), selectedFilePath);
                Scylla::Log->log(TEXT("-> Old file size 0x%08X new file size 0x%08X (%d %%)"), fileSize, newSize, ((newSize * 100) / fileSize));
            }
            else
            {
                Scylla::Log->log(TEXT("Rebuild failed, cannot save file %s"), selectedFilePath);
                MessageBox(TEXT("Rebuild failed. Cannot save file."), TEXT("Failure"), MB_ICONERROR);
            }
        }
        else
        {
            Scylla::Log->log(TEXT("Rebuild failed, cannot read file %s"), selectedFilePath);
            MessageBox(TEXT("Rebuild failed. Cannot read file."), TEXT("Failure"), MB_ICONERROR);
        }

    }
}

void MainGui::dumpFixActionHandler()
{
    if (!selectedProcess)
        return;

    if (TreeImports.GetCount() < 2)
    {
        Scylla::Log->log(TEXT("Nothing to rebuild"));
        return;
    }

    TCHAR newFilePath[MAX_PATH];
    TCHAR selectedFilePath[MAX_PATH];
    LPCTSTR fileFilter;
    DWORD_PTR modBase;
    const DWORD_PTR entrypoint = EditOEPAddress.GetValue();

    if (ProcessAccessHelp::selectedModule)
    {
        modBase = ProcessAccessHelp::selectedModule->modBaseAddr;
        fileFilter = filterDll;
    }
    else
    {
        modBase = ProcessAccessHelp::targetImageBase;
        fileFilter = filterExe;
    }

    getCurrentModulePath(stringBuffer, _countof(stringBuffer));
    if (showFileDialog(selectedFilePath, false, nullptr, fileFilter, nullptr, stringBuffer))
    {
        _tcscpy_s(newFilePath, selectedFilePath);

        LPCTSTR extension = nullptr;

        const LPTSTR dot = _tcsrchr(newFilePath, TEXT('.'));
        if (dot)
        {
            *dot = L'\0';
            extension = selectedFilePath + (dot - newFilePath); //wcsrchr(selectedFilePath, L'.');
        }

        _tcscat_s(newFilePath, TEXT("_SCY"));

        if (extension)
        {
            _tcscat_s(newFilePath, extension);
        }

        ImportRebuilder importRebuild(selectedFilePath);

        if (Scylla::config[IAT_FIX_AND_OEP_FIX].isTrue())
        {
            importRebuild.setEntryPointRva(static_cast<DWORD>(entrypoint - modBase));
        }

        if (Scylla::config[OriginalFirstThunk_SUPPORT].isTrue())
        {
            importRebuild.enableOFTSupport();
        }

        if (Scylla::config[SCAN_DIRECT_IMPORTS].isTrue() && Scylla::config[FIX_DIRECT_IMPORTS_UNIVERSAL].isTrue())
        {
            if (iatReferenceScan.numberOfFoundDirectImports() > 0)
            {
                importRebuild.iatReferenceScan = &iatReferenceScan;
                importRebuild.BuildDirectImportsJumpTable = true;
            }
        }

        if (Scylla::config[CREATE_NEW_IAT_IN_SECTION].isTrue())
        {
            importRebuild.iatReferenceScan = &iatReferenceScan;

            const DWORD_PTR addressIAT = EditIATAddress.GetValue();
            const DWORD sizeIAT = EditIATSize.GetValue();
            importRebuild.enableNewIatInSection(addressIAT, sizeIAT);
        }


        if (importRebuild.rebuildImportTable(newFilePath, importsHandling.moduleList))
        {
            Scylla::Log->log(TEXT("Import Rebuild success %s"), newFilePath);
        }
        else
        {
            Scylla::Log->log(TEXT("Import Rebuild failed %s"), selectedFilePath);
            MessageBox(TEXT("Import Rebuild failed"), TEXT("Failure"), MB_ICONERROR);
        }
    }
}

void MainGui::enableDialogControls(BOOL value)
{
    BOOL valButton = value ? TRUE : FALSE;

    GetDlgItem(IDC_BTN_PICKDLL).EnableWindow(valButton);
    GetDlgItem(IDC_BTN_DUMP).EnableWindow(valButton);
    GetDlgItem(IDC_BTN_FIXDUMP).EnableWindow(valButton);
    GetDlgItem(IDC_BTN_IATAUTOSEARCH).EnableWindow(valButton);
    GetDlgItem(IDC_BTN_GETIMPORTS).EnableWindow(valButton);
    GetDlgItem(IDC_BTN_SUSPECTIMPORTS).EnableWindow(valButton);
    GetDlgItem(IDC_BTN_INVALIDIMPORTS).EnableWindow(valButton);
    GetDlgItem(IDC_BTN_CLEARIMPORTS).EnableWindow(valButton);

    CMenuHandle menu = GetMenu();

    const UINT valMenu = value ? MF_ENABLED : MF_GRAYED;

    menu.EnableMenuItem(ID_FILE_DUMP, valMenu);
    menu.EnableMenuItem(ID_FILE_DUMPMEMORY, valMenu);
    menu.EnableMenuItem(ID_FILE_DUMPSECTION, valMenu);
    menu.EnableMenuItem(ID_FILE_FIXDUMP, valMenu);
    menu.EnableMenuItem(ID_IMPORTS_INVALIDATESELECTED, valMenu);
    menu.EnableMenuItem(ID_IMPORTS_CUTSELECTED, valMenu);
    menu.EnableMenuItem(ID_IMPORTS_SAVETREE, valMenu);
    menu.EnableMenuItem(ID_IMPORTS_LOADTREE, valMenu);
    menu.EnableMenuItem(ID_MISC_DLLINJECTION, valMenu);
    menu.EnableMenuItem(ID_MISC_DISASSEMBLER, valMenu);
    menu.GetSubMenu(MenuImportsOffsetTrace).EnableMenuItem(MenuImportsTraceOffsetScylla, MF_BYPOSITION | valMenu);
    menu.GetSubMenu(MenuImportsOffsetTrace).EnableMenuItem(MenuImportsTraceOffsetImpRec, MF_BYPOSITION | valMenu);

    //not yet implemented
    GetDlgItem(IDC_BTN_AUTOTRACE).EnableWindow(FALSE);
    menu.EnableMenuItem(ID_TRACE_AUTOTRACE, MF_GRAYED);
}

CTreeItem MainGui::findTreeItem(CPoint pt, bool screenCoordinates)
{
    if (screenCoordinates)
    {
        TreeImports.ScreenToClient(&pt);
    }

    UINT flags;
    CTreeItem over = TreeImports.HitTest(pt, &flags);
    if (over)
    {
        if (!(flags & TVHT_ONITEM))
        {
            over.m_hTreeItem = nullptr;
        }
    }

    return over;
}

void MainGui::showAboutDialog()
{
    AboutGui dlgAbout;
    dlgAbout.DoModal();
}

void MainGui::showDonateDialog()
{
    DonateGui dlgDonate;
    dlgDonate.DoModal();
}

void MainGui::dllInjectActionHandler()
{
    if (!selectedProcess)
        return;

    TCHAR selectedFilePath[MAX_PATH];

    getCurrentModulePath(stringBuffer, _countof(stringBuffer));
    if (showFileDialog(selectedFilePath, false, nullptr, filterDll, nullptr, stringBuffer))
    {
        const auto hMod = DllInjection::dllInjection(ProcessAccessHelp::hProcess, selectedFilePath);
        if (hMod && Scylla::config[DLL_INJECTION_AUTO_UNLOAD].isTrue())
        {
            if (!DllInjection::unloadDllInProcess(ProcessAccessHelp::hProcess, hMod))
            {
                Scylla::Log->log(TEXT("DLL unloading failed, target %s"), selectedFilePath);
            }
        }

        if (hMod)
        {
            Scylla::Log->log(TEXT("DLL Injection was successful, target %s"), selectedFilePath);
        }
        else
        {
            Scylla::Log->log(TEXT("DLL Injection failed, target %s"), selectedFilePath);
        }
    }
}

void MainGui::disassemblerActionHandler()
{
    const DWORD_PTR oep = EditOEPAddress.GetValue();
    DisassemblerGui disGuiDlg(oep, &apiReader);
    disGuiDlg.DoModal();
}

void MainGui::optionsActionHandler()
{
    OptionsGui dlgOptions;
    dlgOptions.DoModal();
}

void MainGui::clearImportsActionHandler()
{
    importsHandling.clearAllImports();
    updateStatusBar();
}

void MainGui::pluginActionHandler(int menuItem)
{
    if (!selectedProcess)
        return;

    DllInjectionPlugin dllInjectionPlugin;

    std::vector<Plugin> &scyllaPluginList = Scylla::plugins.getScyllaPluginList();
    std::vector<Plugin> &imprecPluginList = Scylla::plugins.getImprecPluginList();

    menuItem -= PLUGIN_MENU_BASE_ID;

    DllInjectionPlugin::hProcess = ProcessAccessHelp::hProcess;
    dllInjectionPlugin.apiReader = &apiReader;

    if (menuItem < static_cast<int>(scyllaPluginList.size()))
    {
        //scylla plugin
        dllInjectionPlugin.injectPlugin(scyllaPluginList[menuItem], importsHandling.moduleList, selectedProcess->imageBase, selectedProcess->imageSize);
    }
    else
    {
#ifndef _WIN64

        menuItem -= static_cast<int>(scyllaPluginList.size());
        //imprec plugin
        dllInjectionPlugin.injectImprecPlugin(imprecPluginList[menuItem], importsHandling.moduleList, selectedProcess->imageBase, selectedProcess->imageSize);

#endif
    }

    importsHandling.scanAndFixModuleList();
    importsHandling.displayAllImports();
    updateStatusBar();
}

bool MainGui::getCurrentModulePath(LPTSTR buffer, size_t bufferSize) const
{
    if (!selectedProcess)
        return false;

    if (ProcessAccessHelp::selectedModule)
    {
        _tcscpy_s(buffer, bufferSize, ProcessAccessHelp::selectedModule->fullPath);
    }
    else
    {
        _tcscpy_s(buffer, bufferSize, selectedProcess->fullPath);
    }

    const LPTSTR slash = _tcsrchr(buffer, TEXT('\\'));
    if (slash)
    {
        *(slash + 1) = TEXT('\0');
    }

    return true;
}

void MainGui::checkSuspendProcess()
{
    if (Scylla::config[SUSPEND_PROCESS_FOR_DUMPING].isTrue())
    {
        if (!ProcessAccessHelp::suspendProcess())
        {
            Scylla::Log->log(TEXT("Error: Cannot suspend process."));
        }
        else
        {
            isProcessSuspended = true;
            Scylla::Log->log(TEXT("Suspending process successful, please resume manually."));
        }
    }
}

void MainGui::setDialogIATAddressAndSize(DWORD_PTR addressIAT, DWORD sizeIAT)
{
    EditIATAddress.SetValue(addressIAT);
    EditIATSize.SetValue(sizeIAT);

    _stprintf_s(stringBuffer, TEXT("IAT found:\r\n\r\nStart: ") PRINTF_DWORD_PTR_FULL TEXT("\r\nSize: 0x%04X (%d) "), addressIAT, sizeIAT, sizeIAT);
    MessageBox(stringBuffer, TEXT("IAT found"), MB_ICONINFORMATION);
}

bool MainGui::isIATOutsidePeImage(DWORD_PTR addressIAT) const
{
    DWORD_PTR minAdd, maxAdd;

    if (ProcessAccessHelp::selectedModule)
    {
        minAdd = ProcessAccessHelp::selectedModule->modBaseAddr;
        maxAdd = minAdd + ProcessAccessHelp::selectedModule->modBaseSize;
    }
    else
    {
        minAdd = selectedProcess->imageBase;
        maxAdd = minAdd + selectedProcess->imageSize;
    }

    return !(addressIAT > minAdd && addressIAT < maxAdd);
}

bool MainGui::getCurrentDefaultDumpFilename(LPTSTR buffer, size_t bufferSize) const
{
    if (!selectedProcess)
        return false;

    LPTSTR fullPath;

    if (ProcessAccessHelp::selectedModule)
    {
        fullPath = ProcessAccessHelp::selectedModule->fullPath;
    }
    else
    {
        fullPath = selectedProcess->fullPath;
    }

    TCHAR * temp = _tcsrchr(fullPath, TEXT('\\'));
    if (temp)
    {
        temp++;
        _tcscpy_s(buffer, bufferSize, temp);

        temp = _tcsrchr(buffer, TEXT('.'));
        if (temp)
        {
            *temp = 0;

            if (ProcessAccessHelp::selectedModule)
            {
                _tcscat_s(buffer, bufferSize, TEXT("_dump.dll"));
            }
            else
            {
                _tcscat_s(buffer, bufferSize, TEXT("_dump.exe"));
            }
        }


        return true;
    }

    return false;
}
