#include "PickApiGui.h"
#include "StringConversion.h"

PickApiGui::PickApiGui(const std::vector<ModuleInfo> &moduleList) : moduleList(moduleList)
{
    selectedApi = nullptr;
}

BOOL PickApiGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
    DoDataExchange(); // attach controls
    DlgResize_Init(true, true);

    fillDllComboBox(ComboDllSelect);

    CenterWindow();
    return TRUE;
}

void PickApiGui::OnOK(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    actionApiSelected();
}

void PickApiGui::OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    EndDialog(0);
}

void PickApiGui::OnDllListSelected(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    const int indexDll = ComboDllSelect.GetCurSel();
    if (indexDll != CB_ERR)
    {
        fillApiListBox(ListApiSelect, moduleList[indexDll].apiList);
        EditApiFilter.SetWindowText(TEXT(""));
    }
}

void PickApiGui::OnApiListDoubleClick(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    actionApiSelected();
}

void PickApiGui::OnApiFilterUpdated(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    const int indexDll = ComboDllSelect.GetCurSel();
    if (indexDll == CB_ERR)
        return;

    std::vector<ApiInfo *> newApis;
    TCHAR filter[MAX_PATH];

    const int lenFilter = EditApiFilter.GetWindowText(filter, _countof(filter));
    if (lenFilter > 0)
    {
        const std::vector<ApiInfo *> &apis = moduleList[indexDll].apiList;

        for (auto api : apis)
        {
            if (api->name[0] != '\0')
            {
                TCHAR str[MAX_PATH];
                StringConversion::ToTStr(api->name, str, MAX_PATH);
                if (!_tcsnicmp(str, filter, lenFilter))
                {
                    newApis.push_back(api);
                }
            }
            else
            {
                TCHAR buf[6];
                _stprintf_s(buf, TEXT("%04X"), api->ordinal);
                if (!_tcsnicmp(buf, filter, lenFilter))
                {
                    newApis.push_back(api);
                }
            }
        }
    }
    else
    {
        newApis = moduleList[indexDll].apiList;
    }

    fillApiListBox(ListApiSelect, newApis);
}

void PickApiGui::actionApiSelected()
{
    const int indexDll = ComboDllSelect.GetCurSel();
    int indexApi;
    if (ListApiSelect.GetCount() == 1)
    {
        indexApi = 0;
    }
    else
    {
        indexApi = ListApiSelect.GetCurSel();
    }
    if (indexDll != CB_ERR && indexApi != LB_ERR)
    {
        selectedApi = reinterpret_cast<ApiInfo *>(ListApiSelect.GetItemData(indexApi));
        EndDialog(1);
    }
}

void PickApiGui::fillDllComboBox(CComboBox& combo) const
{
    combo.ResetContent();

    for (const auto& i : moduleList)
    {
        combo.AddString(i.fullPath);
    }
}

void PickApiGui::fillApiListBox(CListBox& list, const std::vector<ApiInfo *> &apis)
{
    list.ResetContent();

    for (auto api : apis)
    {
        int item;
        if (api->name[0] != '\0')
        {
            TCHAR str[MAX_PATH];
            StringConversion::ToTStr(api->name, str, MAX_PATH);
            item = list.AddString(str);
        }
        else
        {
            TCHAR buf[6];
            _stprintf_s(buf, TEXT("#%04X"), api->ordinal);
            item = list.AddString(buf);
        }
        list.SetItemData(item, reinterpret_cast<DWORD_PTR>(api));
    }
}
