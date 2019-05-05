#pragma once

#include <windows.h>
#include "resource.h"

// WTL
#include <atlbase.h>       // base ATL classes
#include <atlapp.h>        // base WTL classes
#include <atlwin.h>        // ATL GUI classes
#include <atlcrack.h>      // WTL enhanced msg map macros
#include <atlctrls.h>      // WTL controls
#include <atlddx.h>        // WTL dialog data exchange

class AboutGui : public CDialogImpl<AboutGui>, public CWinDataExchange<AboutGui>
{
public:
	enum { IDD = IDD_DLG_ABOUT };

	BEGIN_DDX_MAP(AboutGui)
		DDX_CONTROL_HANDLE(IDC_STATIC_ABOUT_TITLE, StaticTitle)
		DDX_CONTROL_HANDLE(IDC_STATIC_DEVELOPED, StaticDeveloped)
		DDX_CONTROL_HANDLE(IDC_STATIC_GREETINGS, StaticGreetings)
		DDX_CONTROL_HANDLE(IDC_STATIC_YODA, StaticYoda)
		DDX_CONTROL_HANDLE(IDC_SYSLINK_VISIT, LinkVisit)
		DDX_CONTROL_HANDLE(IDC_SYSLINK_DISTORM, LinkDistorm)
		DDX_CONTROL_HANDLE(IDC_SYSLINK_WTL, LinkWTL)
		DDX_CONTROL_HANDLE(IDC_SYSLINK_SILK, LinkSilk)
		DDX_CONTROL_HANDLE(IDC_SYSLINK_TINYXML, LinkTinyxml)
		DDX_CONTROL_HANDLE(IDC_SYSLINK_LICENSE, LinkLicense)
	END_DDX_MAP()

	BEGIN_MSG_MAP(AboutGui)
		MSG_WM_INITDIALOG(OnInitDialog)
		MSG_WM_CLOSE(OnClose)

		NOTIFY_HANDLER_EX(IDC_SYSLINK_DISTORM, NM_CLICK, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_DISTORM, NM_RETURN, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_WTL, NM_CLICK, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_WTL, NM_RETURN, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_SILK, NM_CLICK, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_SILK, NM_RETURN, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_TINYXML, NM_CLICK, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_TINYXML, NM_RETURN, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_VISIT, NM_CLICK, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_VISIT, NM_RETURN, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_LICENSE, NM_CLICK, OnLink)
		NOTIFY_HANDLER_EX(IDC_SYSLINK_LICENSE, NM_RETURN, OnLink)
		COMMAND_ID_HANDLER_EX(IDOK, OnExit)
		COMMAND_ID_HANDLER_EX(IDCANCEL, OnExit)
	END_MSG_MAP()

protected:

	// Controls

	CStatic StaticTitle;
	CStatic StaticDeveloped;
	CStatic StaticGreetings;
	CStatic StaticYoda;

	CLinkCtrl LinkVisit;
	CLinkCtrl LinkDistorm;
	CLinkCtrl LinkWTL;
	CLinkCtrl LinkSilk;
	CLinkCtrl LinkTinyxml;
	CLinkCtrl LinkLicense;

	CToolTipCtrl TooltipDistorm;
	CToolTipCtrl TooltipWTL;
	CToolTipCtrl TooltipSilk;
	CToolTipCtrl TooltipTinyxml;
	CToolTipCtrl TooltipLicense;

	// Handles

	CFontHandle FontBold;

	// Texts

	static const TCHAR TEXT_VISIT[];
	static const TCHAR TEXT_DEVELOPED[];
	static const TCHAR TEXT_CREDIT_DISTORM[];
	static const TCHAR TEXT_CREDIT_YODA[];
	static const TCHAR TEXT_CREDIT_WTL[];
	static const TCHAR TEXT_CREDIT_SILK[];
	static const TCHAR TEXT_GREETINGS[];
	static const TCHAR TEXT_LICENSE[];
	static const TCHAR TEXT_TINYXML[];

	// URLs

	static const TCHAR URL_VISIT1[];
	static const TCHAR URL_VISIT2[];
	static const TCHAR URL_DISTORM[];
	static const TCHAR URL_WTL[];
	static const TCHAR URL_SILK[];
	static const TCHAR URL_LICENSE[];
	static const TCHAR URL_TINYXML[];

protected:

	// Message handlers

	BOOL OnInitDialog(CWindow wndFocus, LPARAM lInitParam);
	void OnClose();
	LRESULT OnLink(NMHDR* pnmh) const;
	void OnExit(UINT uNotifyCode, int nID, CWindow wndCtl);

	// GUI helpers

	void setupLinks();
    static void setLinkURL(CLinkCtrl& link, LPCTSTR url, int index = 0);
    static void setupTooltip(CToolTipCtrl tooltip, CWindow window, LPCTSTR text);
};
