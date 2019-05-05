#include "DisassemblerGui.h"
#include <algorithm>
#include <Psapi.h>

#include "ProcessAccessHelp.h"
#include "Architecture.h"
#include "Scylla.h"
#include "StringConversion.h"


DisassemblerGui::DisassemblerGui(DWORD_PTR startAddress, ApiReader * apiReaderObject)
{
    apiReader = apiReaderObject;
    addressHistoryIndex = 0;
    addressHistory.push_back(startAddress);
    hMenuDisassembler.LoadMenu(IDR_MENU_DISASSEMBLER);

    initAddressCommentList();
}

BOOL DisassemblerGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
    DoDataExchange(); // attach controls
    DlgResize_Init(true, true);

    addColumnsToDisassembler(ListDisassembler);
    displayDisassembly();

    EditAddress.SetValue(addressHistory[addressHistoryIndex]);

    CenterWindow();

    return TRUE;
}

void DisassemblerGui::OnContextMenu(CWindow wnd, CPoint point)
{
    if (wnd.GetDlgCtrlID() == IDC_LIST_DISASSEMBLER)
    {
        const int selection = ListDisassembler.GetSelectionMark();
        if (selection == -1) // no item selected
            return;

        if (point.x == -1 && point.y == -1) // invoked by keyboard
        {
            ListDisassembler.EnsureVisible(selection, TRUE);
            ListDisassembler.GetItemPosition(selection, &point);
            ListDisassembler.ClientToScreen(&point);
        }

        CMenuHandle hSub = hMenuDisassembler.GetSubMenu(0);
        BOOL menuItem = hSub.TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, point.x, point.y, wnd);
        if (menuItem)
        {
            int column = -1;
            switch (menuItem)
            {
            case ID__DIS_ADDRESS:
                column = COL_ADDRESS;
                break;
            case ID__DIS_SIZE:
                column = COL_INSTRUCTION_SIZE;
                break;
            case ID__DIS_OPCODES:
                column = COL_OPCODES;
                break;
            case ID__DIS_INSTRUCTIONS:
                column = COL_INSTRUCTION;
                break;
            case ID__DIS_FOLLOW:
                followInstruction(selection);
                break;
            case ID__DIS_DISASSEMBLEHERE:
            {
                disassembleNewAddress(static_cast<DWORD_PTR>(ProcessAccessHelp::decomposerResult[selection].addr));
            }
            default: ;
            }
            if (column != -1)
            {
                tempBuffer[0] = TEXT('\0');
                ListDisassembler.GetItemText(selection, column, tempBuffer, _countof(tempBuffer));
                copyToClipboard(tempBuffer);
            }
        }
    }
}

LRESULT DisassemblerGui::OnNMCustomdraw(NMHDR* pnmh)
{
    LRESULT pResult = 0;
    const auto lpLVCustomDraw = reinterpret_cast<LPNMLVCUSTOMDRAW>(pnmh);

    switch (lpLVCustomDraw->nmcd.dwDrawStage)
    {
    case CDDS_ITEMPREPAINT:
    case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
    {
        const DWORD_PTR itemIndex = lpLVCustomDraw->nmcd.dwItemSpec;

        if (lpLVCustomDraw->iSubItem == COL_INSTRUCTION)
        {
            doColorInstruction(lpLVCustomDraw, itemIndex);
        }
        else
        {
            lpLVCustomDraw->clrText = CLR_DEFAULT;
            lpLVCustomDraw->clrTextBk = CLR_DEFAULT;
        }
    }
    break;
    default: ;
    }


    pResult |= CDRF_NOTIFYPOSTPAINT;
    pResult |= CDRF_NOTIFYITEMDRAW;
    pResult |= CDRF_NOTIFYSUBITEMDRAW;

    return pResult;
}

void DisassemblerGui::OnExit(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    EndDialog(0);
}

void DisassemblerGui::OnDisassemble(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    const DWORD_PTR address = EditAddress.GetValue();
    if (address)
    {
        disassembleNewAddress(address);
    }
}

void DisassemblerGui::disassembleNewAddress(DWORD_PTR address)
{
    if (addressHistory[addressHistory.size() - 1] != address)
    {
        addressHistory.push_back(address);
        addressHistoryIndex = static_cast<int>(addressHistory.size()) - 1;
        EditAddress.SetValue(addressHistory[addressHistoryIndex]);

        if (!displayDisassembly())
        {
            MessageBox(TEXT("Cannot disassemble memory at this address"), TEXT("Error"), MB_ICONERROR);
        }
    }

}

void DisassemblerGui::OnDisassembleForward(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    if (addressHistoryIndex != (addressHistory.size() - 1))
    {
        addressHistoryIndex++;
        EditAddress.SetValue(addressHistory[addressHistoryIndex]);
        if (!displayDisassembly())
        {
            MessageBox(TEXT("Cannot disassemble memory at this address"), TEXT("Error"), MB_ICONERROR);
        }
    }
}

void DisassemblerGui::OnDisassembleBack(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    if (addressHistoryIndex != 0)
    {
        addressHistoryIndex--;
        EditAddress.SetValue(addressHistory[addressHistoryIndex]);
        if (!displayDisassembly())
        {
            MessageBox(TEXT("Cannot disassemble memory at this address"), TEXT("Error"), MB_ICONERROR);
        }
    }
}

void DisassemblerGui::addColumnsToDisassembler(CListViewCtrl& list)
{
    list.SetExtendedListViewStyle(LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

    list.InsertColumn(COL_ADDRESS, TEXT("Address"), LVCFMT_LEFT);
    list.InsertColumn(COL_INSTRUCTION_SIZE, TEXT("Size"), LVCFMT_CENTER);
    list.InsertColumn(COL_OPCODES, TEXT("Opcodes"), LVCFMT_LEFT);
    list.InsertColumn(COL_INSTRUCTION, TEXT("Instructions"), LVCFMT_LEFT);
    list.InsertColumn(COL_COMMENT, TEXT("Comment"), LVCFMT_LEFT);
}

bool DisassemblerGui::displayDisassembly()
{
    ListDisassembler.DeleteAllItems();

    if (!ProcessAccessHelp::readMemoryFromProcess(addressHistory[addressHistoryIndex], sizeof(data), data))
        return false;

    if (!ProcessAccessHelp::decomposeMemory(data, sizeof(data), addressHistory[addressHistoryIndex]))
        return false;

    if (!ProcessAccessHelp::disassembleMemory(data, sizeof(data), addressHistory[addressHistoryIndex]))
        return false;

    for (unsigned int i = 0; i < ProcessAccessHelp::decodedInstructionsCount; i++)
    {
        _stprintf_s(tempBuffer, PRINTF_DWORD_PTR_FULL, static_cast<uintptr_t>(ProcessAccessHelp::decodedInstructions[i].offset));

        ListDisassembler.InsertItem(i, tempBuffer);

        _stprintf_s(tempBuffer, TEXT("%02d"), ProcessAccessHelp::decodedInstructions[i].size);

        ListDisassembler.SetItemText(i, COL_INSTRUCTION_SIZE, tempBuffer);

        _stprintf_s(tempBuffer, TEXT("%s"), reinterpret_cast<char *>(ProcessAccessHelp::decodedInstructions[i].instructionHex.p));

        toUpperCase(tempBuffer);
        ListDisassembler.SetItemText(i, COL_OPCODES, tempBuffer);

        _stprintf_s(tempBuffer, TEXT("%s%s%s"), reinterpret_cast<char*>(ProcessAccessHelp::decodedInstructions[i].mnemonic.p), ProcessAccessHelp::decodedInstructions[i].operands.length != 0 ? " " : "", reinterpret_cast<char*>(ProcessAccessHelp::decodedInstructions[i].operands.p));

        toUpperCase(tempBuffer);
        ListDisassembler.SetItemText(i, COL_INSTRUCTION, tempBuffer);

        tempBuffer[0] = 0;
        if (getDisassemblyComment(i))
        {
            ListDisassembler.SetItemText(i, COL_COMMENT, tempBuffer);
        }
    }

    ListDisassembler.SetColumnWidth(COL_ADDRESS, LVSCW_AUTOSIZE_USEHEADER);
    ListDisassembler.SetColumnWidth(COL_INSTRUCTION_SIZE, LVSCW_AUTOSIZE_USEHEADER);
    ListDisassembler.SetColumnWidth(COL_OPCODES, 140);
    ListDisassembler.SetColumnWidth(COL_INSTRUCTION, LVSCW_AUTOSIZE_USEHEADER);
    ListDisassembler.SetColumnWidth(COL_COMMENT, LVSCW_AUTOSIZE_USEHEADER);

    return true;
}

void DisassemblerGui::copyToClipboard(LPCTSTR text)
{
    if (OpenClipboard())
    {
        EmptyClipboard();
        const size_t len = _tcslen(text);
        const HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(WCHAR));
        if (hMem)
        {
            StringConversion::ToWStr(text, static_cast<LPWSTR>(GlobalLock(hMem)), len + 1);
            GlobalUnlock(hMem);
            if (!SetClipboardData(CF_UNICODETEXT, hMem))
            {
                GlobalFree(hMem);
            }
        }
        CloseClipboard();
    }
}

void DisassemblerGui::toUpperCase(LPTSTR lowercase)
{
    for (size_t i = 0; i < _tcslen(lowercase); i++)
    {
        if (lowercase[i] != TEXT('x'))
        {
            lowercase[i] = _totupper(lowercase[i]);
        }
    }
}

void DisassemblerGui::doColorInstruction(LPNMLVCUSTOMDRAW lpLVCustomDraw, DWORD_PTR itemIndex)
{
    if (ProcessAccessHelp::decomposerResult[itemIndex].flags == FLAG_NOT_DECODABLE)
    {
        lpLVCustomDraw->clrText = RGB(255, 255, 255); // white text
        lpLVCustomDraw->clrTextBk = RGB(255, 0, 0); // red background
    }
    else if (META_GET_FC(ProcessAccessHelp::decomposerResult[itemIndex].meta) == FC_RET)
    {
        lpLVCustomDraw->clrTextBk = RGB(0, 255, 255); // aqua
    }
    else if (META_GET_FC(ProcessAccessHelp::decomposerResult[itemIndex].meta) == FC_CALL)
    {
        lpLVCustomDraw->clrTextBk = RGB(255, 255, 0); // yellow
    }
    else if (META_GET_FC(ProcessAccessHelp::decomposerResult[itemIndex].meta) == FC_UNC_BRANCH)
    {
        lpLVCustomDraw->clrTextBk = RGB(0x32, 0xCD, 0x32); // limegreen
    }
    else if (META_GET_FC(ProcessAccessHelp::decomposerResult[itemIndex].meta) == FC_CND_BRANCH)
    {
        lpLVCustomDraw->clrTextBk = RGB(0xAD, 0xFF, 0x2F); // greenyellow
    }

}

void DisassemblerGui::followInstruction(int index)
{
    DWORD_PTR address = 0;
    DWORD_PTR addressTemp;
    const DWORD type = META_GET_FC(ProcessAccessHelp::decomposerResult[index].meta);

    if (ProcessAccessHelp::decomposerResult[index].flags != FLAG_NOT_DECODABLE)
    {
        if (type == FC_CALL || type == FC_UNC_BRANCH || type == FC_CND_BRANCH)
        {
#ifdef _WIN64
            if (ProcessAccessHelp::decomposerResult[index].flags & FLAG_RIP_RELATIVE)
            {
                addressTemp = INSTRUCTION_GET_RIP_TARGET(&ProcessAccessHelp::decomposerResult[index]);

                if (!ProcessAccessHelp::readMemoryFromProcess(addressTemp, sizeof(DWORD_PTR), &address))
                {
                    address = 0;
                }
            }
#endif

            if (ProcessAccessHelp::decomposerResult[index].ops[0].type == O_PC)
            {
                address = static_cast<DWORD_PTR>(INSTRUCTION_GET_TARGET(&ProcessAccessHelp::decomposerResult[index]));
            }

            if (ProcessAccessHelp::decomposerResult[index].ops[0].type == O_DISP)
            {
                addressTemp = static_cast<DWORD_PTR>(ProcessAccessHelp::decomposerResult[index].disp);

                if (!ProcessAccessHelp::readMemoryFromProcess(addressTemp, sizeof(DWORD_PTR), &address))
                {
                    address = 0;
                }
            }

            if (address != 0)
            {
                disassembleNewAddress(address);
            }
        }

    }
}

bool DisassemblerGui::getDisassemblyComment(unsigned int index)
{
    DWORD_PTR address = 0;
    DWORD_PTR addressTemp;
    const DWORD type = META_GET_FC(ProcessAccessHelp::decomposerResult[index].meta);

    tempBuffer[0] = 0;

    if (ProcessAccessHelp::decomposerResult[index].flags != FLAG_NOT_DECODABLE)
    {
        if (type == FC_CALL || type == FC_UNC_BRANCH || type == FC_CND_BRANCH)
        {
            if (ProcessAccessHelp::decomposerResult[index].flags & FLAG_RIP_RELATIVE)
            {
#ifdef _WIN64
                addressTemp = static_cast<DWORD_PTR>(INSTRUCTION_GET_RIP_TARGET(&ProcessAccessHelp::decomposerResult[index]));

                _stprintf_s(tempBuffer, TEXT("-> ") PRINTF_DWORD_PTR_FULL, addressTemp);

                if (ProcessAccessHelp::readMemoryFromProcess(addressTemp, sizeof(DWORD_PTR), &address))
                {
                    _stprintf_s(tempBuffer, TEXT("%s -> ") PRINTF_DWORD_PTR_FULL, tempBuffer, address);
                }
#endif
            }
            else if (ProcessAccessHelp::decomposerResult[index].ops[0].type == O_PC)
            {
                address = static_cast<DWORD_PTR>(INSTRUCTION_GET_TARGET(&ProcessAccessHelp::decomposerResult[index]));
                _stprintf_s(tempBuffer, TEXT("-> ") PRINTF_DWORD_PTR_FULL, address);
            }
            else if (ProcessAccessHelp::decomposerResult[index].ops[0].type == O_DISP)
            {
                addressTemp = static_cast<DWORD_PTR>(ProcessAccessHelp::decomposerResult[index].disp);

                _stprintf_s(tempBuffer, TEXT("-> ") PRINTF_DWORD_PTR_FULL, addressTemp);

                address = 0;
                if (ProcessAccessHelp::readMemoryFromProcess(addressTemp, sizeof(DWORD_PTR), &address))
                {
                    _stprintf_s(tempBuffer, TEXT("%s -> ") PRINTF_DWORD_PTR_FULL, tempBuffer, address);
                }
            }
        }
    }

    if (address != 0)
    {
        analyzeAddress(address, tempBuffer);
        return true;
    }
    else
    {
        return false;
    }
}

void DisassemblerGui::initAddressCommentList()
{
    HMODULE * hMods = nullptr;
    TCHAR target[MAX_PATH];

    const DWORD numHandles = ProcessAccessHelp::getModuleHandlesFromProcess(ProcessAccessHelp::hProcess, &hMods);
    if (numHandles == 0)
    {
        return;
    }

    for (DWORD i = 0; i < numHandles; i++)
    {
        if (ProcessAccessHelp::targetImageBase != reinterpret_cast<DWORD_PTR>(hMods[i]))
        {
            if (GetModuleFileNameEx(ProcessAccessHelp::hProcess, hMods[i], target, _countof(target)))
            {
                addModuleAddressCommentEntry(reinterpret_cast<DWORD_PTR>(hMods[i]), static_cast<DWORD>(ProcessAccessHelp::getSizeOfImageProcess(ProcessAccessHelp::hProcess,
                                                                                                                              reinterpret_cast<DWORD_PTR>(hMods[i]))), target);
            }
            else
            {
                Scylla::debugLog.log(TEXT("DllInjection::getModuleHandle :: GetModuleFileNameExW failed 0x%X"), GetLastError());
            }
        }
    }

    std::sort(addressCommentList.begin(), addressCommentList.end());
}

void DisassemblerGui::addModuleAddressCommentEntry(DWORD_PTR address, DWORD moduleSize, LPCTSTR modulePath)
{
    DisassemblerAddressComment commentObj{};
    //get filename
    const TCHAR* slash = _tcsrchr(modulePath, TEXT('\\'));
    if (slash)
    {
        modulePath = slash + 1;
    }

    _tcscpy_s(commentObj.comment, _countof(commentObj.comment), modulePath);
    commentObj.address = address;
    commentObj.type = ADDRESS_TYPE_MODULE;
    commentObj.moduleSize = moduleSize;

    addressCommentList.push_back(commentObj);
}

void DisassemblerGui::analyzeAddress(DWORD_PTR address, LPTSTR comment)
{
    if (addressCommentList[0].address > address) //list is sorted, TODO: binary search
    {
        return;
    }
    bool isSuspect;
    ApiInfo * api = apiReader->getApiByVirtualAddress(address, &isSuspect);

    if (api != nullptr && api != reinterpret_cast<ApiInfo *>(1))
    {
        if (api->name[0] == 0)
        {
            _stprintf_s(tempBuffer, TEXT("%s = %s.%04X"), comment, api->module->getFilename(), api->ordinal);
        }
        else
        {
            _stprintf_s(tempBuffer, TEXT("%s = %s.%s"), comment, api->module->getFilename(), api->name);
        }
    }
    else
    {
        for (size_t i = 0; i < addressCommentList.size(); i++)
        {
            if (addressCommentList[i].type == ADDRESS_TYPE_MODULE)
            {
                if (address >= addressCommentList[i].address && address < (addressCommentList[i].address + addressCommentList[i].moduleSize))
                {
                    _stprintf_s(tempBuffer, TEXT("%s = %s"), comment, addressCommentList[i].comment);
                    return;
                }
            }
        }
    }
}
