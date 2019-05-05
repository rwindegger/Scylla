#include "AboutGui.h"

#include "Scylla.h"
#include "Architecture.h"
#include "StringConversion.h"

const TCHAR AboutGui::TEXT_VISIT[] = TEXT("Visit <a>German Reversing Newbies</a> and <a>Seek n Destroy</a>");
const TCHAR AboutGui::TEXT_DEVELOPED[] = TEXT("Developed with Microsoft Visual Studio, written in pure C/C++");
const TCHAR AboutGui::TEXT_CREDIT_DISTORM[] = TEXT("This tool uses the <a>diStorm disassembler library</a> v3");
const TCHAR AboutGui::TEXT_CREDIT_YODA[] = TEXT("Thanks yoda for your PE Rebuilder engine");
const TCHAR AboutGui::TEXT_CREDIT_SILK[] = TEXT("The small icons are taken from the <a>Silk icon package</a>");
const TCHAR AboutGui::TEXT_CREDIT_WTL[] = TEXT("<a>Windows Template Library</a> v10 is used for the GUI");
const TCHAR AboutGui::TEXT_GREETINGS[] = TEXT("Greetz: metr0, G36KV and all from the gRn Team");
const TCHAR AboutGui::TEXT_LICENSE[] = TEXT("Scylla is licensed under the <a>GNU General Public License v3</a>");
const TCHAR AboutGui::TEXT_TINYXML[] = TEXT("XML support is provided by <a>TinyXML2</a>");

const TCHAR AboutGui::URL_VISIT1[] = TEXT("http://www.c0rk.org/portal/a/");
const TCHAR AboutGui::URL_VISIT2[] = TEXT("http://forum.tuts4you.com");
const TCHAR AboutGui::URL_DISTORM[] = TEXT("https://github.com/gdabah/distorm/");
const TCHAR AboutGui::URL_WTL[] = TEXT("https://sourceforge.net/projects/wtl/");
const TCHAR AboutGui::URL_SILK[] = TEXT("http://www.famfamfam.com");
const TCHAR AboutGui::URL_LICENSE[] = TEXT("http://www.gnu.org/licenses/gpl-3.0.html");
const TCHAR AboutGui::URL_TINYXML[] = TEXT("https://github.com/leethomason/tinyxml2");

BOOL AboutGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
    DoDataExchange(); // attach controls

    // Create a bold font for the title
    LOGFONT lf;
    CFontHandle font = StaticTitle.GetFont();
    font.GetLogFont(&lf);
    lf.lfWeight = FW_BOLD;
    FontBold.CreateFontIndirect(&lf);

    StaticTitle.SetFont(FontBold, FALSE);

    StaticTitle.SetWindowText(APPNAME TEXT(" ") ARCHITECTURE TEXT(" ") APPVERSION);
    StaticDeveloped.SetWindowText(TEXT_DEVELOPED);
    StaticGreetings.SetWindowText(TEXT_GREETINGS);
    StaticYoda.SetWindowText(TEXT_CREDIT_YODA);

    setupLinks();

    CenterWindow();

    // Set focus to the OK button
    GotoDlgCtrl(GetDlgItem(IDOK));
    return FALSE;
}

void AboutGui::OnClose()
{
    TooltipDistorm.DestroyWindow();
    TooltipWTL.DestroyWindow();
    TooltipSilk.DestroyWindow();
    TooltipLicense.DestroyWindow();
    FontBold.DeleteObject();
    EndDialog(0);
}

LRESULT AboutGui::OnLink(NMHDR* pnmh) const
{
    const auto link = reinterpret_cast<NMLINK*>(pnmh);

    TCHAR tmp[2084];
    StringConversion::ToTStr(link->item.szUrl, tmp, 2084);
    ShellExecute(nullptr, TEXT("open"), tmp, nullptr, nullptr, SW_SHOW);
    return 0;
}

void AboutGui::OnExit(UINT uNotifyCode, int nID, CWindow wndCtl)
{
    SendMessage(WM_CLOSE);
}

void AboutGui::setupLinks()
{
    // Set link text (must be set before assigning URLs)
    LinkVisit.SetWindowText(TEXT_VISIT);
    LinkDistorm.SetWindowText(TEXT_CREDIT_DISTORM);
    LinkWTL.SetWindowText(TEXT_CREDIT_WTL);
    LinkSilk.SetWindowText(TEXT_CREDIT_SILK);
    LinkTinyxml.SetWindowText(TEXT_TINYXML);
    LinkLicense.SetWindowText(TEXT_LICENSE);

    // Assign URLs to anchors in the link text
    setLinkURL(LinkVisit, URL_VISIT1, 0);
    setLinkURL(LinkVisit, URL_VISIT2, 1);
    setLinkURL(LinkDistorm, URL_DISTORM);
    setLinkURL(LinkWTL, URL_WTL);
    setLinkURL(LinkSilk, URL_SILK);
    setLinkURL(LinkTinyxml, URL_TINYXML);
    setLinkURL(LinkLicense, URL_LICENSE);

    // Create tooltips for the links
    TooltipDistorm.Create(m_hWnd, nullptr, nullptr, TTS_NOPREFIX, WS_EX_TOPMOST);
    TooltipWTL.Create(m_hWnd, nullptr, nullptr, TTS_NOPREFIX, WS_EX_TOPMOST);
    TooltipSilk.Create(m_hWnd, nullptr, nullptr, TTS_NOPREFIX, WS_EX_TOPMOST);
    TooltipTinyxml.Create(m_hWnd, nullptr, nullptr, TTS_NOPREFIX, WS_EX_TOPMOST);
    TooltipLicense.Create(m_hWnd, nullptr, nullptr, TTS_NOPREFIX, WS_EX_TOPMOST);

    // Assign control and text to the tooltips
    setupTooltip(TooltipDistorm, LinkDistorm, URL_DISTORM);
    setupTooltip(TooltipWTL, LinkWTL, URL_WTL);
    setupTooltip(TooltipSilk, LinkSilk, URL_SILK);
    setupTooltip(TooltipTinyxml, LinkTinyxml, URL_TINYXML);
    setupTooltip(TooltipLicense, LinkLicense, URL_LICENSE);
}

void AboutGui::setLinkURL(CLinkCtrl& link, LPCTSTR url, int index)
{
    LITEM item;
    item.mask = LIF_ITEMINDEX | LIF_URL;
    item.iLink = index;
    StringConversion::ToWStr(url, item.szUrl, 2084);
    link.SetItem(&item);
}

void AboutGui::setupTooltip(CToolTipCtrl tooltip, CWindow window, LPCTSTR text)
{
    CToolInfo ti(TTF_SUBCLASS, window);

    window.GetClientRect(&ti.rect);
    ti.lpszText = const_cast<LPTSTR>(text);
    tooltip.AddTool(ti);
}
