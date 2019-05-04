#include "ConfigurationHolder.h"

#include <shlwapi.h>
#include "Architecture.h"
#include "Scylla.h"
#include <tchar.h>

const TCHAR ConfigurationHolder::CONFIG_FILE_SECTION_NAME[] = TEXT("SCYLLA_CONFIG");

ConfigurationHolder::ConfigurationHolder(LPCTSTR fileName)
{
	config[USE_PE_HEADER_FROM_DISK]     = Configuration(TEXT("USE_PE_HEADER_FROM_DISK"),      Configuration::Boolean);
	config[DEBUG_PRIVILEGE]             = Configuration(TEXT("DEBUG_PRIVILEGE"),              Configuration::Boolean);
	config[CREATE_BACKUP]               = Configuration(TEXT("CREATE_BACKUP"),                Configuration::Boolean);
	config[DLL_INJECTION_AUTO_UNLOAD]   = Configuration(TEXT("DLL_INJECTION_AUTO_UNLOAD"),    Configuration::Boolean);
	config[UPDATE_HEADER_CHECKSUM]      = Configuration(TEXT("UPDATE_HEADER_CHECKSUM"),       Configuration::Boolean);
	config[IAT_SECTION_NAME]            = Configuration(TEXT("IAT_SECTION_NAME"),             Configuration::String);
	config[REMOVE_DOS_HEADER_STUB]      = Configuration(TEXT("REMOVE_DOS_HEADER_STUB"),       Configuration::Boolean);
	config[IAT_FIX_AND_OEP_FIX]         = Configuration(TEXT("IAT_FIX_AND_OEP_FIX"),          Configuration::Boolean);
	config[SUSPEND_PROCESS_FOR_DUMPING] = Configuration(TEXT("SUSPEND_PROCESS_FOR_DUMPING"),  Configuration::Boolean);
	config[OriginalFirstThunk_SUPPORT]  = Configuration(TEXT("OriginalFirstThunk_SUPPORT"),	 Configuration::Boolean);
	config[USE_ADVANCED_IAT_SEARCH]     = Configuration(TEXT("USE_ADVANCED_IAT_SEARCH"),	     Configuration::Boolean);
	config[SCAN_DIRECT_IMPORTS]			= Configuration(TEXT("SCAN_DIRECT_IMPORTS"),			 Configuration::Boolean);
	config[FIX_DIRECT_IMPORTS_NORMAL]			= Configuration(TEXT("FIX_DIRECT_IMPORTS_NORMAL"),			 Configuration::Boolean);
	config[FIX_DIRECT_IMPORTS_UNIVERSAL]		= Configuration(TEXT("FIX_DIRECT_IMPORTS_UNIVERSAL"),			 Configuration::Boolean);
    config[CREATE_NEW_IAT_IN_SECTION]	=   Configuration(TEXT("CREATE_NEW_IAT_IN_SECTION"),	 Configuration::Boolean);
    config[DONT_CREATE_NEW_SECTION] 	=   Configuration(TEXT("DONT_CREATE_NEW_SECTION"),	 Configuration::Boolean);
    config[APIS_ALWAYS_FROM_DISK]	    =   Configuration(TEXT("APIS_ALWAYS_FROM_DISK"),	     Configuration::Boolean);
	buildConfigFilePath(fileName);
}

bool ConfigurationHolder::loadConfiguration()
{
    if (configPath[0] == TEXT('\0'))
	{
		return false;
	}

	for (auto& mapIter : config)
	{
		Configuration& configObject = mapIter.second;
		loadConfig(configObject);
	}

	return true;
}

bool ConfigurationHolder::saveConfiguration() const
{
    if (configPath[0] == TEXT('\0'))
	{
		return false;
	}

	for (const auto& mapIter : config)
	{
		const Configuration& configObject = mapIter.second;
		if (!saveConfig(configObject))
		{
			return false;
		}
	}

	return true;
}

Configuration& ConfigurationHolder::operator[](ConfigOption option)
{
	return config[option];
}

const Configuration& ConfigurationHolder::operator[](ConfigOption option) const
{
	static const Configuration dummy;

	std::map<ConfigOption, Configuration>::const_iterator found = config.find(option);
	if(found != config.end())
	{
		return found->second;
	}
	else
	{
		return dummy;
	}
}

bool ConfigurationHolder::saveNumericToConfigFile(const Configuration & configObject, int nBase) const
{
	TCHAR buf[21]; // UINT64_MAX in dec has 20 digits

	if (nBase == 16)
	{
		_stprintf_s(buf, PRINTF_DWORD_PTR_FULL, configObject.getNumeric());
	}
	else
	{
#pragma warning(suppress : 4477)
		_stprintf_s(buf, PRINTF_INTEGER, configObject.getNumeric());
	}

    const BOOL ret = WritePrivateProfileString(CONFIG_FILE_SECTION_NAME, configObject.getName(), buf, configPath);
	return !!ret;
}

bool ConfigurationHolder::readNumericFromConfigFile(Configuration & configObject, int nBase) const
{
	TCHAR buf[21]; // UINT64_MAX in dec has 20 digits
    const DWORD read = GetPrivateProfileString(CONFIG_FILE_SECTION_NAME, configObject.getName(), TEXT(""), buf, _countof(buf), configPath);

	if (read > 0 && _tcslen(buf) > 0)
	{
#ifdef _WIN64
		configObject.setNumeric(_tcstoui64(buf, nullptr, nBase));
#else
		configObject.setNumeric(_tcstoul(buf, NULL, nBase));
#endif
		return true;
	}

	return false;
}

bool ConfigurationHolder::saveStringToConfigFile(const Configuration & configObject) const
{
    const BOOL ret = WritePrivateProfileString(CONFIG_FILE_SECTION_NAME, configObject.getName(), configObject.getString(), configPath);
	return !!ret;
}

bool ConfigurationHolder::readStringFromConfigFile(Configuration & configObject) const
{
	TCHAR buf[Configuration::CONFIG_STRING_LENGTH];
    const DWORD read = GetPrivateProfileString(CONFIG_FILE_SECTION_NAME, configObject.getName(), TEXT(""), buf, _countof(buf), configPath);
	if(read > 0 && _tcslen(buf) > 0)
	{
		configObject.setString(buf);
		return true;
	}

	return false;
}

bool ConfigurationHolder::readBooleanFromConfigFile(Configuration & configObject) const
{
    const UINT val = GetPrivateProfileInt(CONFIG_FILE_SECTION_NAME, configObject.getName(), 0, configPath);
	configObject.setBool(val != 0);
	return true;
}

bool ConfigurationHolder::saveBooleanToConfigFile(const Configuration & configObject) const
{
    const TCHAR *boolValue = configObject.isTrue() ? TEXT("1") : TEXT("0");
    const BOOL ret = WritePrivateProfileString(CONFIG_FILE_SECTION_NAME, configObject.getName(), boolValue, configPath);
	return !!ret;
}

bool ConfigurationHolder::loadConfig(Configuration & configObject) const
{
	switch (configObject.getType())
	{
	case Configuration::String:
		return readStringFromConfigFile(configObject);
	case Configuration::Boolean:
		return readBooleanFromConfigFile(configObject);
	case Configuration::Decimal:
		return readNumericFromConfigFile(configObject, 10);
	case Configuration::Hexadecimal:
		return readNumericFromConfigFile(configObject, 16);
	default:
		return false;
	}
}

bool ConfigurationHolder::saveConfig(const Configuration & configObject) const
{
	switch (configObject.getType())
	{
	case Configuration::String:
		return saveStringToConfigFile(configObject);
	case Configuration::Boolean:
		return saveBooleanToConfigFile(configObject);
	case Configuration::Decimal:
		return saveNumericToConfigFile(configObject, 10);
	case Configuration::Hexadecimal:
		return saveNumericToConfigFile(configObject, 16);
	default:
		return false;
	}
}

bool ConfigurationHolder::buildConfigFilePath(LPCTSTR fileName)
{
	ZeroMemory(configPath, sizeof configPath);

	if (!GetModuleFileName(nullptr, configPath, _countof(configPath)))
	{
		Scylla::debugLog.log(TEXT("buildConfigFilePath :: GetModuleFileName failed %d"), GetLastError());
		return false;
	}

	PathRemoveFileSpec(configPath);
	PathAppend(configPath, fileName);

	return true;
}
