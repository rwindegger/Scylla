#include "PickDllGui.h"

#include "Architecture.h"

PickDllGui::PickDllGui(std::vector<ModuleInfo> &moduleList) : moduleList(moduleList)
{
    selectedModule = nullptr;

    prevColumn = -1;
    ascending = true;
}

BOOL PickDllGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
    DoDataExchange(); // attach controls
    DlgResize_Init(true, true);

    addColumnsToModuleList(ListDLLSelect);
    displayModuleList(ListDLLSelect);

    CenterWindow();
    return TRUE;
}

LRESULT PickDllGui::OnListDllColumnClicked(NMHDR* pnmh)
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
    ListDLLSelect.SortItems(&listviewCompareFunc, MAKEWORD(column, ascending));

    return 0;
}

LRESULT PickDllGui::OnListDllDoubleClick(NMHDR* pnmh)
{
    const auto ia = reinterpret_cast<NMITEMACTIVATE*>(pnmh);
    LVHITTESTINFO hti;
    hti.pt = ia->ptAction;
    const int clicked = ListDLLSelect.HitTest(&hti);
    if (clicked != -1)
    {
        selectedModule = reinterpret_cast<ModuleInfo *>(ListDLLSelect.GetItemData(clicked));
        EndDialog(1);
    }
    return 0;
}

void PickDllGui::OnOK(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    const int index = ListDLLSelect.GetSelectionMark();
    if (index != -1)
    {
        selectedModule = reinterpret_cast<ModuleInfo *>(ListDLLSelect.GetItemData(index));
        EndDialog(1);
    }
}

void PickDllGui::OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    EndDialog(0);
}

void PickDllGui::addColumnsToModuleList(CListViewCtrl& list)
{
    list.SetExtendedListViewStyle(LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

    list.InsertColumn(COL_NAME, TEXT("Name"), LVCFMT_LEFT);
    list.InsertColumn(COL_IMAGEBASE, TEXT("ImageBase"), LVCFMT_CENTER);
    list.InsertColumn(COL_IMAGESIZE, TEXT("ImageSize"), LVCFMT_CENTER);
    list.InsertColumn(COL_PATH, TEXT("Path"), LVCFMT_LEFT);
}

void PickDllGui::displayModuleList(CListViewCtrl& list) const
{
    TCHAR temp[20];

    list.DeleteAllItems();

    int count = 0;

    for (std::vector<ModuleInfo>::const_iterator iter = moduleList.begin(); iter != moduleList.end(); iter++, count++)
    {
        list.InsertItem(count, iter->getFilename());

        _stprintf_s(temp, PRINTF_DWORD_PTR_FULL, iter->modBaseAddr);

        list.SetItemText(count, COL_IMAGEBASE, temp);

        _stprintf_s(temp, TEXT("%08X"), iter->modBaseSize);
        list.SetItemText(count, COL_IMAGESIZE, temp);

        list.SetItemText(count, COL_PATH, iter->fullPath);

        list.SetItemData(count, reinterpret_cast<DWORD_PTR>(&(*iter)));
    }

    list.SetColumnWidth(COL_NAME, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_IMAGEBASE, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_IMAGESIZE, LVSCW_AUTOSIZE_USEHEADER);
    list.SetColumnWidth(COL_PATH, LVSCW_AUTOSIZE_USEHEADER);
}

// lParamSort - lo-byte: column, hi-byte: sort-order
int PickDllGui::listviewCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
    const auto module1 = reinterpret_cast<ModuleInfo *>(lParam1);
    const auto module2 = reinterpret_cast<ModuleInfo *>(lParam2);

    const int column = LOBYTE(lParamSort);
    const bool ascending = (HIBYTE(lParamSort) == TRUE);

    int diff = 0;

    switch (column)
    {
    case COL_NAME:
        diff = _tcsicmp(module1->getFilename(), module2->getFilename());
        break;
    case COL_IMAGEBASE:
        diff = module1->modBaseAddr < module2->modBaseAddr ? -1 : 1;
        break;
    case COL_IMAGESIZE:
        diff = module1->modBaseSize < module2->modBaseSize ? -1 : 1;
        break;
    case COL_PATH:
        diff = _tcsicmp(module1->fullPath, module2->fullPath);
        break;
    default: ;
    }

    return ascending ? diff : -diff;
}
