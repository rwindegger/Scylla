#include "DumpSectionGui.h"

#include "Architecture.h"
#include "ProcessAccessHelp.h"
#include "PeParser.h"


bool PeSection::highlightVirtualSize() const
{
    //highlight big virtual sizes -> anti-dump protection
    return (virtualSize > 0x2000000);
}

std::vector<PeSection> & DumpSectionGui::getSectionList()
{
    return sectionList;
}

DumpSectionGui::DumpSectionGui()
    : selectedSection(nullptr)
    , isEditing(false)
    , editingSubItem(0)
    , valueBeforeEditing(0)
    , prevColumn(0)
    , ascending(false)
{
    imageBase = 0;
    entryPoint = 0;
    fullpath[0] = 0;
}

DumpSectionGui::~DumpSectionGui()
{
    sectionList.clear();
}

BOOL DumpSectionGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
    DoDataExchange(); // attach controls
    DlgResize_Init(true, true);

    addColumnsToSectionList(ListSectionSelect);
    displaySectionList(ListSectionSelect);

    selectOrDeselectAll();

    isEditing = false;
    selectedSection = nullptr;

    CenterWindow();
    return TRUE;
}

LRESULT DumpSectionGui::OnListSectionColumnClicked(NMHDR* pnmh)
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
    ListSectionSelect.SortItems(&listviewCompareFunc, MAKEWORD(column, ascending));

    return 0;
}
LRESULT DumpSectionGui::OnListSectionClick(NMHDR* pnmh)
{
    //int index = ListSectionSelect.GetSelectionMark();
    //if (index != -1)
    //{

    //}
    return 0;
}

LRESULT DumpSectionGui::OnListDoubleClick(NMHDR* pnmh)
{
    LVHITTESTINFO hti;
    RECT rect, rect1, rect2;
    const auto ia = reinterpret_cast<NMITEMACTIVATE*>(pnmh);

    editingSubItem = ia->iSubItem;

    if (editingSubItem == COL_NAME || editingSubItem == COL_VA)
    {
        return 0;
    }



    hti.pt = ia->ptAction;
    const int clicked = ListSectionSelect.HitTest(&hti);
    if (clicked != -1)
    {
        selectedSection = reinterpret_cast<PeSection *>(ListSectionSelect.GetItemData(clicked));
    }


    ListSectionSelect.GetSubItemRect(ia->iItem, ia->iSubItem, LVIR_BOUNDS, &rect);

    //Get the Rectange of the listControl
    ListSectionSelect.GetWindowRect(&rect1);
    //Get the Rectange of the Dialog
    GetWindowRect(&rect2);

    isEditing = true;

    switch (editingSubItem)
    {
    case COL_VSize:
        valueBeforeEditing = selectedSection->virtualSize;
        break;
    case COL_RVA:
        valueBeforeEditing = selectedSection->rawAddress;
        break;
    case COL_RSize:
        valueBeforeEditing = selectedSection->rawSize;
        break;
    case COL_Characteristics:
        valueBeforeEditing = selectedSection->characteristics;
        break;
    default:
        valueBeforeEditing = 0;
    }

    EditListControl.SetValue(valueBeforeEditing);

    EditListControl.SetWindowPos(HWND_TOP, rect.left + 7, rect.top + 7, rect.right - rect.left, rect.bottom - rect.top, NULL);
    EditListControl.ShowWindow(SW_SHOW);
    EditListControl.SetFocus();

    return 0;
}

void DumpSectionGui::OnSectionSelectAll(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    selectOrDeselectAll();
}

void DumpSectionGui::OnEditList(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    switch (uNotifyCode)
    {
    case EN_KILLFOCUS:
    {
        isEditing = false;

        updateEditedItem();

        EditListControl.ShowWindow(SW_HIDE);
    }
    break;
    default: ;
    }
}

void DumpSectionGui::OnOK(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    if (isEditing) //EN_KILLFOCUS not sent?
    {
        updateEditedItem();
    }

    updateCheckState();

    EndDialog(1);
}
void DumpSectionGui::OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    EndDialog(0);
}

int DumpSectionGui::listviewCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
    const auto module1 = reinterpret_cast<PeSection *>(lParam1);
    const auto module2 = reinterpret_cast<PeSection *>(lParam2);

    const int column = LOBYTE(lParamSort);
    const bool ascending = (HIBYTE(lParamSort) == TRUE);

    int diff = 0;

    switch (column)
    {
    case COL_NAME:
        diff = _tcsicmp(module1->name, module2->name);
        break;
    case COL_VA:
        diff = module1->virtualAddress < module2->virtualAddress ? -1 : 1;
        break;
    case COL_VSize:
        diff = module1->virtualSize < module2->virtualSize ? -1 : 1;
        break;
    case COL_RVA:
        diff = module1->rawAddress < module2->rawAddress ? -1 : 1;
        break;
    case COL_RSize:
        diff = module1->rawSize < module2->rawSize ? -1 : 1;
        break;
    case COL_Characteristics:
        diff = module1->characteristics < module2->characteristics ? -1 : 1;
        break;
    default: ;
    }

    return ascending ? diff : -diff;
}

void DumpSectionGui::addColumnsToSectionList(CListViewCtrl& list)
{
    list.SetExtendedListViewStyle(LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES | LVS_EX_GRIDLINES, LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES | LVS_EX_GRIDLINES);

    list.InsertColumn(COL_NAME, TEXT("Name"), LVCFMT_CENTER);
    list.InsertColumn(COL_VA, TEXT("Virtual Address"), LVCFMT_CENTER);
    list.InsertColumn(COL_VSize, TEXT("Virtual Size"), LVCFMT_CENTER);
    list.InsertColumn(COL_RVA, TEXT("Raw Address"), LVCFMT_CENTER);
    list.InsertColumn(COL_RSize, TEXT("Raw Size"), LVCFMT_CENTER);
    list.InsertColumn(COL_Characteristics, TEXT("Characteristics"), LVCFMT_CENTER);
}

void DumpSectionGui::displaySectionList(CListViewCtrl& list)
{
    int count = 0;
    TCHAR temp[20];

    list.DeleteAllItems();

    if (sectionList.empty())
    {
        getAllSectionsFromFile();
    }

    for (std::vector<PeSection>::const_iterator iter = sectionList.begin(); iter != sectionList.end(); iter++, count++)
    {
        list.InsertItem(count, iter->name);

        _stprintf_s(temp, PRINTF_DWORD_PTR_FULL, iter->virtualAddress);
        list.SetItemText(count, COL_VA, temp);

        _stprintf_s(temp, TEXT("%08X"), iter->virtualSize);
        list.SetItemText(count, COL_VSize, temp);

        _stprintf_s(temp, TEXT("%08X"), iter->rawAddress);
        list.SetItemText(count, COL_RVA, temp);

        _stprintf_s(temp, TEXT("%08X"), iter->rawSize);
        list.SetItemText(count, COL_RSize, temp);

        _stprintf_s(temp, TEXT("%08X"), iter->characteristics);
        list.SetItemText(count, COL_Characteristics, temp);

        list.SetItemData(count, reinterpret_cast<DWORD_PTR>(&(*iter)));
    }

    list.SetColumnWidth(COL_NAME, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_VA, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_VSize, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_RVA, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_RSize, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_Characteristics, LVSCW_AUTOSIZE_USEHEADER);

}

LRESULT DumpSectionGui::OnNMCustomdraw(NMHDR* pnmh)
{
    LRESULT pResult = 0;
    const auto lpLVCustomDraw = reinterpret_cast<LPNMLVCUSTOMDRAW>(pnmh);

    switch (lpLVCustomDraw->nmcd.dwDrawStage)
    {
    case CDDS_ITEMPREPAINT:
    case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
    {
        const auto vectorIndex = static_cast<unsigned int>(lpLVCustomDraw->nmcd.dwItemSpec);

        if (lpLVCustomDraw->iSubItem == COL_VSize)
        {
            if (sectionList[vectorIndex].highlightVirtualSize())
            {
                lpLVCustomDraw->clrText = RGB(255, 255, 255); // white text
                lpLVCustomDraw->clrTextBk = RGB(255, 0, 0); // red background
            }
        }
        else
        {
            lpLVCustomDraw->clrText = CLR_DEFAULT;
            lpLVCustomDraw->clrTextBk = CLR_DEFAULT;
        }
    }
    break;
    default:
        break;
    }


    pResult |= CDRF_NOTIFYPOSTPAINT;
    pResult |= CDRF_NOTIFYITEMDRAW;
    pResult |= CDRF_NOTIFYSUBITEMDRAW;

    return pResult;
}

void DumpSectionGui::getAllSectionsFromFile()
{
    PeSection peSection{};

    if (sectionList.empty())
    {
        sectionList.reserve(3);
    }
    else
    {
        sectionList.clear();
    }

    PeParser peFile(fullpath);

    if (peFile.isValidPeFile())
    {
        std::vector<PeFileSection> & listSectionHeader = peFile.getSectionHeaderList();

        for (WORD i = 0; i < peFile.getNumberOfSections(); i++)
        {
            peFile.getSectionName(i, peSection.name, _countof(peSection.name));

            peSection.virtualAddress = imageBase + listSectionHeader[i].sectionHeader.VirtualAddress;
            peSection.virtualSize = listSectionHeader[i].sectionHeader.Misc.VirtualSize;
            peSection.rawAddress = listSectionHeader[i].sectionHeader.PointerToRawData;
            peSection.rawSize = listSectionHeader[i].sectionHeader.SizeOfRawData;
            peSection.characteristics = listSectionHeader[i].sectionHeader.Characteristics;
            peSection.isDumped = true;

            sectionList.push_back(peSection);
        }
    }
    else
    {
        MessageBox(fullpath, TEXT("Not a valid PE -> This should never happen"), MB_ICONERROR);
    }

}

void DumpSectionGui::updateEditedItem()
{
    if (selectedSection)
    {
        const DWORD newValue = EditListControl.GetValue();

        if (valueBeforeEditing != newValue)
        {
            switch (editingSubItem)
            {
            case COL_VSize:
                selectedSection->virtualSize = newValue;
                break;
            case COL_RVA:
                selectedSection->rawAddress = newValue;
                break;
            case COL_RSize:
                selectedSection->rawSize = newValue;
                break;
            case COL_Characteristics:
                selectedSection->characteristics = newValue;
                break;
            default: ;
            }

            displaySectionList(ListSectionSelect);
            selectOrDeselectAll();
        }
    }
}

void DumpSectionGui::updateCheckState()
{
    for (size_t i = 0; i < sectionList.size(); i++)
    {
        PeSection * pesection = reinterpret_cast<PeSection *>(ListSectionSelect.GetItemData(static_cast<int>(i)));
        pesection->isDumped = ListSectionSelect.GetCheckState(static_cast<int>(i)) == TRUE;
    }
}

void DumpSectionGui::selectOrDeselectAll()
{
    BOOL checkState = ListSectionSelect.GetCheckState(static_cast<int>(0)) ? FALSE : TRUE;

    for (size_t i = 0; i < sectionList.size(); i++)
    {
        ListSectionSelect.SetCheckState(static_cast<int>(i), checkState);
    }
}
