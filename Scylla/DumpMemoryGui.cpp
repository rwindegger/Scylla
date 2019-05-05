#include "DumpMemoryGui.h"
#include <Psapi.h>

#include "Architecture.h"
#include "ProcessAccessHelp.h"
#include "PeParser.h"
#include "Scylla.h"

TCHAR DumpMemoryGui::protectionString[100];
LPCTSTR DumpMemoryGui::MemoryUndefined = TEXT("UNDEF");
LPCTSTR DumpMemoryGui::MemoryUnknown = TEXT("UNKNOWN");
LPCTSTR DumpMemoryGui::MemoryStateValues[] = { TEXT("COMMIT"),TEXT("FREE"),TEXT("RESERVE") };
LPCTSTR DumpMemoryGui::MemoryTypeValues[] = { TEXT("IMAGE"),TEXT("MAPPED"),TEXT("PRIVATE") };
LPCTSTR DumpMemoryGui::MemoryProtectionValues[] = { TEXT("EXECUTE"),TEXT("EXECUTE_READ"),TEXT("EXECUTE_READWRITE"),TEXT("EXECUTE_WRITECOPY"),TEXT("NOACCESS"),TEXT("READONLY"),TEXT("READWRITE"),TEXT("WRITECOPY"),TEXT("GUARD"),TEXT("NOCACHE"),TEXT("WRITECOMBINE") };


DumpMemoryGui::DumpMemoryGui()
    : dumpFilename{}
    , selectedMemory(nullptr)
    , prevColumn(0)
    , ascending(false)
    , forceDump(false)
{
    dumpedMemory = nullptr;
    dumpedMemorySize = 0;
    deviceNameResolver = new DeviceNameResolver();
}

DumpMemoryGui::~DumpMemoryGui()
{
    if (dumpedMemory)
    {
        delete[] dumpedMemory;
    }

    if (deviceNameResolver)
    {
        delete deviceNameResolver;
    }

    memoryList.clear();
}
BOOL DumpMemoryGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
    DoDataExchange(); // attach controls
    DlgResize_Init(true, true);

    addColumnsToMemoryList(ListMemorySelect);
    displayMemoryList(ListMemorySelect);

    forceDump = false;
    DoDataExchange(DDX_LOAD);

    EditMemoryAddress.SetValue(ProcessAccessHelp::targetImageBase);
    EditMemorySize.SetValue(static_cast<DWORD>(ProcessAccessHelp::targetSizeOfImage));

    CenterWindow();
    return TRUE;
}

void DumpMemoryGui::addColumnsToMemoryList(CListViewCtrl& list)
{
    list.SetExtendedListViewStyle(LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

    list.InsertColumn(COL_ADDRESS, TEXT("Address"), LVCFMT_CENTER);
    list.InsertColumn(COL_SIZE, TEXT("Size"), LVCFMT_CENTER);
    list.InsertColumn(COL_FILENAME, TEXT("File"), LVCFMT_LEFT);
    list.InsertColumn(COL_PESECTION, TEXT("PE Section"), LVCFMT_LEFT);

    list.InsertColumn(COL_TYPE, TEXT("Type"), LVCFMT_CENTER);
    list.InsertColumn(COL_PROTECTION, TEXT("Protection"), LVCFMT_CENTER);
    list.InsertColumn(COL_STATE, TEXT("State"), LVCFMT_CENTER);

    list.InsertColumn(COL_MAPPED_FILE, TEXT("Mapped File"), LVCFMT_LEFT);
}

void DumpMemoryGui::displayMemoryList(CListViewCtrl& list)
{
    int count = 0;
    TCHAR temp[20];
    list.DeleteAllItems();

    getMemoryList();

    std::vector<Memory>::const_iterator iter;

    for (iter = memoryList.begin(); iter != memoryList.end(); iter++, count++)
    {
        _stprintf_s(temp, PRINTF_DWORD_PTR_FULL, iter->address);
        list.InsertItem(count, temp);

        _stprintf_s(temp, TEXT("%08X"), iter->size);
        list.SetItemText(count, COL_SIZE, temp);

        list.SetItemText(count, COL_FILENAME, iter->filename);
        list.SetItemText(count, COL_PESECTION, iter->peSection);

        if (iter->state == MEM_FREE)
        {
            list.SetItemText(count, COL_TYPE, MemoryUndefined);
        }
        else
        {
            list.SetItemText(count, COL_TYPE, getMemoryTypeString(iter->type));
        }

        if ((iter->state == MEM_RESERVE) || (iter->state == MEM_FREE))
        {
            list.SetItemText(count, COL_PROTECTION, MemoryUndefined);
        }
        else
        {
            list.SetItemText(count, COL_PROTECTION, getMemoryProtectionString(iter->protect));
        }

        list.SetItemText(count, COL_STATE, getMemoryStateString(iter->state));

        list.SetItemText(count, COL_MAPPED_FILE, iter->mappedFilename);

        list.SetItemData(count, reinterpret_cast<DWORD_PTR>(&(*iter)));
    }

    list.SetColumnWidth(COL_ADDRESS, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_SIZE, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_FILENAME, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_PESECTION, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_TYPE, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_PROTECTION, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_STATE, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_MAPPED_FILE, LVSCW_AUTOSIZE_USEHEADER);
}

LPCTSTR DumpMemoryGui::getMemoryTypeString(DWORD value)
{
    switch (value)
    {
    case MEM_IMAGE:
        return MemoryTypeValues[TYPE_IMAGE];
    case MEM_MAPPED:
        return MemoryTypeValues[TYPE_MAPPED];
    case MEM_PRIVATE:
        return MemoryTypeValues[TYPE_PRIVATE];
    default:
        return MemoryUnknown;
    }
}
LPCTSTR DumpMemoryGui::getMemoryStateString(DWORD value)
{
    switch (value)
    {
    case MEM_COMMIT:
        return MemoryStateValues[STATE_COMMIT];
    case MEM_FREE:
        return MemoryStateValues[STATE_FREE];
    case MEM_RESERVE:
        return MemoryStateValues[STATE_RESERVE];
    default:
        return MemoryUnknown;
    }
}

LPTSTR DumpMemoryGui::getMemoryProtectionString(DWORD value)
{
    protectionString[0] = 0;

    if (value & PAGE_GUARD)
    {
        _tcscpy_s(protectionString, MemoryProtectionValues[PROT_GUARD]);
        _tcscat_s(protectionString, TEXT(" | "));
        value ^= PAGE_GUARD;
    }
    if (value & PAGE_NOCACHE)
    {
        _tcscpy_s(protectionString, MemoryProtectionValues[PROT_NOCACHE]);
        _tcscat_s(protectionString, TEXT(" | "));
        value ^= PAGE_NOCACHE;
    }
    if (value & PAGE_WRITECOMBINE)
    {
        _tcscpy_s(protectionString, MemoryProtectionValues[PROT_WRITECOMBINE]);
        _tcscat_s(protectionString, TEXT(" | "));
        value ^= PAGE_WRITECOMBINE;
    }

    switch (value)
    {
    case PAGE_EXECUTE:
    {
        _tcscat_s(protectionString, MemoryProtectionValues[PROT_EXECUTE]);
        break;
    }
    case PAGE_EXECUTE_READ:
    {
        _tcscat_s(protectionString, MemoryProtectionValues[PROT_EXECUTE_READ]);
        break;
    }
    case PAGE_EXECUTE_READWRITE:
    {
        _tcscat_s(protectionString, MemoryProtectionValues[PROT_EXECUTE_READWRITE]);
        break;
    }
    case PAGE_EXECUTE_WRITECOPY:
    {
        _tcscat_s(protectionString, MemoryProtectionValues[PROT_EXECUTE_WRITECOPY]);
        break;
    }
    case PAGE_NOACCESS:
    {
        _tcscat_s(protectionString, MemoryProtectionValues[PROT_NOACCESS]);
        break;
    }
    case PAGE_READONLY:
    {
        _tcscat_s(protectionString, MemoryProtectionValues[PROT_READONLY]);
        break;
    }
    case PAGE_READWRITE:
    {
        _tcscat_s(protectionString, MemoryProtectionValues[PROT_READWRITE]);
        break;
    }
    case PAGE_WRITECOPY:
    {
        _tcscat_s(protectionString, MemoryProtectionValues[PROT_WRITECOPY]);
        break;
    }
    default:
    {
        _tcscat_s(protectionString, MemoryUnknown);
    }
    }

    return protectionString;
}

LRESULT DumpMemoryGui::OnListMemoryColumnClicked(NMHDR* pnmh)
{
    const auto list = reinterpret_cast<NMLISTVIEW*>(pnmh);
    const int column = list->iSubItem;

    if (column == prevColumn)
    {
        ascending = !ascending;
    }
    else
    {
        prevColumn = column;
        ascending = true;
    }

    // lo-byte: column, hi-byte: sort-order
    ListMemorySelect.SortItems(&listviewCompareFunc, MAKEWORD(column, ascending));

    return 0;
}
LRESULT DumpMemoryGui::OnListMemoryClick(NMHDR* pnmh)
{
    const int index = ListMemorySelect.GetSelectionMark();
    if (index != -1)
    {
        selectedMemory = reinterpret_cast<Memory *>(ListMemorySelect.GetItemData(index));
        if (selectedMemory)
        {
            updateAddressAndSize(selectedMemory);
        }

    }
    return 0;
}
void DumpMemoryGui::OnOK(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    DoDataExchange(DDX_SAVE);

    if (EditMemoryAddress.GetValue() == 0 || EditMemorySize.GetValue() == 0)
    {
        wndCtl.MessageBox(TEXT("Textbox is empty!"), TEXT("Error"), MB_ICONERROR);
    }
    else
    {
        if (dumpMemory())
        {
            EndDialog(1);
        }
        else
        {
            wndCtl.MessageBox(TEXT("Reading memory from process failed"), TEXT("Error"), MB_ICONERROR);
        }
    }
}
void DumpMemoryGui::OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    EndDialog(0);
}

void DumpMemoryGui::updateAddressAndSize(Memory * selectedMemory)
{
    EditMemoryAddress.SetValue(selectedMemory->address);
    EditMemorySize.SetValue(selectedMemory->size);
}

int DumpMemoryGui::listviewCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
    const Memory * module1 = reinterpret_cast<Memory *>(lParam1);
    const Memory * module2 = reinterpret_cast<Memory *>(lParam2);

    const int column = LOBYTE(lParamSort);
    const bool ascending = (HIBYTE(lParamSort) == TRUE);

    int diff = 0;

    switch (column)
    {
    case COL_ADDRESS:
        diff = module1->address < module2->address ? -1 : 1;
        break;
    case COL_SIZE:
        diff = module1->size < module2->size ? -1 : 1;
        break;
    case COL_FILENAME:
        diff = _tcsicmp(module1->filename, module2->filename);
        break;
    case COL_PESECTION:
        diff = _tcsicmp(module1->peSection, module2->peSection);
        break;
    case COL_TYPE:
        diff = module1->type < module2->type ? -1 : 1;
        break;
    case COL_PROTECTION:
        diff = module1->protect < module2->protect ? -1 : 1;
        break;
    case COL_STATE:
        diff = _tcsicmp(getMemoryStateString(module1->state), getMemoryStateString(module2->state));
        //diff = module1->state < module2->state ? -1 : 1;
        break;
    case COL_MAPPED_FILE:
        diff = _tcsicmp(module1->mappedFilename, module2->mappedFilename);
        break;
    default: ;
    }

    return ascending ? diff : -diff;
}

void DumpMemoryGui::getMemoryList()
{
    DWORD_PTR address = 0;
    MEMORY_BASIC_INFORMATION memBasic{};
    Memory memory{};
    HMODULE * hMods = nullptr;
    TCHAR target[MAX_PATH];

    if (memoryList.empty())
    {
        memoryList.reserve(20);
    }
    else
    {
        memoryList.clear();
    }

    memory.filename[0] = 0;
    memory.peSection[0] = 0;
    memory.mappedFilename[0] = 0;

    while (VirtualQueryEx(ProcessAccessHelp::hProcess, reinterpret_cast<LPCVOID>(address), &memBasic, sizeof(memBasic)))
    {
        memory.address = reinterpret_cast<DWORD_PTR>(memBasic.BaseAddress);
        memory.type = memBasic.Type;
        memory.state = memBasic.State;
        memory.size = static_cast<DWORD>(memBasic.RegionSize);
        memory.protect = memBasic.Protect;


        if (memory.type == MEM_MAPPED || memory.type == MEM_IMAGE)
        {
            if (!getMappedFilename(&memory))
            {
                memory.mappedFilename[0] = 0;
            }
        }

        memoryList.push_back(memory);

        memory.mappedFilename[0] = 0;

        address += memBasic.RegionSize;
    }

    const DWORD numHandles = ProcessAccessHelp::getModuleHandlesFromProcess(ProcessAccessHelp::hProcess, &hMods);
    if (numHandles == 0)
    {
        return;
    }

    for (DWORD i = 0; i < numHandles; i++)
    {
        if (GetModuleFileNameEx(ProcessAccessHelp::hProcess, hMods[i], target, _countof(target)))
        {
            setModuleName(reinterpret_cast<DWORD_PTR>(hMods[i]), target);
            setAllSectionNames(reinterpret_cast<DWORD_PTR>(hMods[i]), target);
        }
        else
        {
            Scylla::debugLog.log(TEXT("getMemoryList :: GetModuleFileNameEx failed 0x%X"), GetLastError());
        }
    }

    delete[] hMods;
}

void DumpMemoryGui::setSectionName(DWORD_PTR sectionAddress, DWORD sectionSize, LPCTSTR sectionName)
{
    bool found = false;

    for (std::vector<Memory>::const_iterator iter = memoryList.begin(); iter != memoryList.end(); iter++)
    {
        if (!found)
        {
            if ((iter->address <= sectionAddress) && (sectionAddress < (iter->address + iter->size)))
            {
                if (_tcslen(iter->peSection) == 0)
                {
                    _tcscpy_s(const_cast<LPTSTR>(iter->peSection), _countof(iter->peSection), sectionName);
                }
                else
                {
                    _tcscat_s(const_cast<LPTSTR>(iter->peSection), _countof(iter->peSection), TEXT("|"));
                    _tcscat_s(const_cast<LPTSTR>(iter->peSection), _countof(iter->peSection), sectionName);
                }

                found = true;
            }
        }
        else
        {
            if ((sectionSize + sectionAddress) < iter->address)
            {
                break;
            }
            if (_tcslen(iter->peSection) == 0)
            {
                _tcscpy_s(const_cast<LPTSTR>(iter->peSection), _countof(iter->peSection), sectionName);
            }
            else
            {
                _tcscat_s(const_cast<LPTSTR>(iter->peSection), _countof(iter->peSection), TEXT("|"));
                _tcscat_s(const_cast<LPTSTR>(iter->peSection), _countof(iter->peSection), sectionName);
            }
        }

    }
}

void DumpMemoryGui::setModuleName(DWORD_PTR moduleBase, LPCTSTR moduleName)
{
    bool found = false;

    //get filename
    const LPCTSTR slash = _tcsrchr(moduleName, TEXT('\\'));
    if (slash)
    {
        moduleName = slash + 1;
    }

    for (std::vector<Memory>::const_iterator iter = memoryList.begin(); iter != memoryList.end(); iter++)
    {
        if (iter->address == moduleBase)
        {
            found = true;
        }

        if (found)
        {
            if (iter->type == MEM_IMAGE)
            {
                _tcscpy_s(const_cast<LPTSTR>(iter->filename), MAX_PATH, moduleName);
            }
            else
            {
                break;
            }
        }
    }
}

void DumpMemoryGui::setAllSectionNames(DWORD_PTR moduleBase, LPTSTR moduleName)
{
    TCHAR sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };

    PeParser peFile(moduleName);

    if (peFile.isValidPeFile())
    {
        std::vector<PeFileSection> & listSectionHeader = peFile.getSectionHeaderList();

        for (WORD i = 0; i < peFile.getNumberOfSections(); i++)
        {
            peFile.getSectionName(i, sectionName, _countof(sectionName));

            setSectionName(moduleBase + listSectionHeader[i].sectionHeader.VirtualAddress, listSectionHeader[i].sectionHeader.Misc.VirtualSize, sectionName);
        }
    }
    else
    {
        MessageBox(moduleName, TEXT("Not a valid PE -> This should never happen"), MB_ICONERROR);
    }

}

bool DumpMemoryGui::dumpMemory()
{
    const DWORD_PTR address = EditMemoryAddress.GetValue();
    dumpedMemorySize = EditMemorySize.GetValue();

    _stprintf_s(dumpFilename, TEXT("MEM_") PRINTF_DWORD_PTR_FULL TEXT("_") TEXT("%08X"), address, dumpedMemorySize);

    dumpedMemory = new BYTE[dumpedMemorySize];

    if (dumpedMemory)
    {
        if (forceDump)
        {
            return ProcessAccessHelp::readMemoryPartlyFromProcess(address, dumpedMemorySize, dumpedMemory);
        }
        else
        {
            return ProcessAccessHelp::readMemoryFromProcess(address, dumpedMemorySize, dumpedMemory);
        }

    }
    else
    {
        return false;
    }
}

bool DumpMemoryGui::getMappedFilename(Memory* memory) const
{
    TCHAR filename[MAX_PATH] = { 0 };

    if (GetMappedFileName(ProcessAccessHelp::hProcess, reinterpret_cast<LPVOID>(memory->address), filename, _countof(filename)) > 0)
    {
        if (!deviceNameResolver->resolveDeviceLongNameToShort(filename, memory->mappedFilename))
        {
            _tcscpy_s(memory->mappedFilename, filename);
        }

        return true;
    }

    return false;
}
