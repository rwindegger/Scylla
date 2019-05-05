#include "DonateGui.h"

#include "Scylla.h"
#include "Architecture.h"
#include "StringConversion.h"

const TCHAR DonateGui::TEXT_DONATE[] = TEXT("If you like this tool, please feel free to donate some Bitcoins to support this project.\n\n\nBTC Address:\n\n") DONATE_BTC_ADDRESS;


BOOL DonateGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
	DoDataExchange(); // attach controls

	DonateInfo.SetWindowText(TEXT_DONATE);

	CenterWindow();

	// Set focus to button
	GotoDlgCtrl(GetDlgItem(IDC_BUTTON_COPYBTC));
	return FALSE;
}

void DonateGui::OnClose()
{
	EndDialog(0);
}

void DonateGui::OnExit(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	SendMessage(WM_CLOSE);
}

void DonateGui::CopyBtcAddress(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	if(OpenClipboard())
	{
		EmptyClipboard();
	    const size_t len = _tcslen(DONATE_BTC_ADDRESS);
	    const HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(CHAR));
		if(hMem)
		{
            StringConversion::ToCStr(DONATE_BTC_ADDRESS, reinterpret_cast<LPSTR>(hMem), len + 1);
			GlobalUnlock(hMem);
			if(!SetClipboardData(CF_TEXT, hMem))
			{
				GlobalFree(hMem);
			}
		}
		CloseClipboard();
	}
}