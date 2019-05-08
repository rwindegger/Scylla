#include "OptionsGui.h"
#include "configuration_holder.h"
#include "configuration.h"
#include "Scylla.h"

BOOL OptionsGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
	loadOptions();
	DoDataExchange(DDX_LOAD); // show settings

	EditSectionName.LimitText(IMAGE_SIZEOF_SHORT_NAME);

	CenterWindow();

	return TRUE;
}

void OptionsGui::OnOK(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	DoDataExchange(DDX_SAVE);
	saveOptions();
	Scylla::config.saveConfiguration();

	EndDialog(0);
}

void OptionsGui::OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	EndDialog(0);
}

void OptionsGui::saveOptions() const
{
	Scylla::config[config_option::USE_PE_HEADER_FROM_DISK].setBool(usePEHeaderFromDisk);
	Scylla::config[config_option::DEBUG_PRIVILEGE].setBool(debugPrivilege);
	Scylla::config[config_option::CREATE_BACKUP].setBool(createBackup);
	Scylla::config[config_option::DLL_INJECTION_AUTO_UNLOAD].setBool(dllInjectionAutoUnload);
	Scylla::config[config_option::UPDATE_HEADER_CHECKSUM].setBool(updateHeaderChecksum);
	Scylla::config[config_option::IAT_SECTION_NAME].setString(iatSectionName);
	Scylla::config[config_option::REMOVE_DOS_HEADER_STUB].setBool(removeDosHeaderStub);
	Scylla::config[config_option::IAT_FIX_AND_OEP_FIX].setBool(fixIatAndOep);
	Scylla::config[config_option::SUSPEND_PROCESS_FOR_DUMPING].setBool(suspendProcessForDumping);
	Scylla::config[config_option::OriginalFirstThunk_SUPPORT].setBool(oftSupport);
	Scylla::config[config_option::USE_ADVANCED_IAT_SEARCH].setBool(useAdvancedIatSearch);
	Scylla::config[config_option::SCAN_DIRECT_IMPORTS].setBool(scanDirectImports);
	Scylla::config[config_option::FIX_DIRECT_IMPORTS_NORMAL].setBool(fixDirectImportsNormal);
	Scylla::config[config_option::FIX_DIRECT_IMPORTS_UNIVERSAL].setBool(fixDirectImportsUniversal);
	Scylla::config[config_option::CREATE_NEW_IAT_IN_SECTION].setBool(createNewIatInSection);
    Scylla::config[config_option::DONT_CREATE_NEW_SECTION].setBool(dontCreateNewSection);
    Scylla::config[config_option::APIS_ALWAYS_FROM_DISK].setBool(readApisAlwaysFromDisk);
}

void OptionsGui::loadOptions()
{
	usePEHeaderFromDisk    = Scylla::config[config_option::USE_PE_HEADER_FROM_DISK].getBool();
	debugPrivilege         = Scylla::config[config_option::DEBUG_PRIVILEGE].getBool();
	createBackup           = Scylla::config[config_option::CREATE_BACKUP].getBool();
	dllInjectionAutoUnload = Scylla::config[config_option::DLL_INJECTION_AUTO_UNLOAD].getBool();
	updateHeaderChecksum   = Scylla::config[config_option::UPDATE_HEADER_CHECKSUM].getBool();
	_tcsncpy_s(iatSectionName, Scylla::config[config_option::IAT_SECTION_NAME].getString(), _countof(iatSectionName)-1);
	iatSectionName[_countof(iatSectionName) - 1] = L'\0';

	removeDosHeaderStub = Scylla::config[config_option::REMOVE_DOS_HEADER_STUB].getBool();
	fixIatAndOep = Scylla::config[config_option::IAT_FIX_AND_OEP_FIX].getBool();
	suspendProcessForDumping = Scylla::config[config_option::SUSPEND_PROCESS_FOR_DUMPING].getBool();
	oftSupport = Scylla::config[config_option::OriginalFirstThunk_SUPPORT].getBool();
	useAdvancedIatSearch = Scylla::config[config_option::USE_ADVANCED_IAT_SEARCH].getBool();
	scanDirectImports = Scylla::config[config_option::SCAN_DIRECT_IMPORTS].getBool();
	fixDirectImportsNormal = Scylla::config[config_option::FIX_DIRECT_IMPORTS_NORMAL].getBool();
	fixDirectImportsUniversal = Scylla::config[config_option::FIX_DIRECT_IMPORTS_UNIVERSAL].getBool();
	createNewIatInSection = Scylla::config[config_option::CREATE_NEW_IAT_IN_SECTION].getBool();
    dontCreateNewSection = Scylla::config[config_option::DONT_CREATE_NEW_SECTION].getBool();
    readApisAlwaysFromDisk = Scylla::config[config_option::APIS_ALWAYS_FROM_DISK].getBool();
}
