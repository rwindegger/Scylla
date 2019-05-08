#include "configuration_holder.h"
#include "configuration.h"

#include <shlwapi.h>
#include "Architecture.h"
#include "Scylla.h"
#include <tchar.h>

const TCHAR configuration_holder::CONFIG_FILE_SECTION_NAME[] = TEXT("SCYLLA_CONFIG");

configuration_holder::configuration_holder(LPCTSTR fileName)
{
    config[config_option::USE_PE_HEADER_FROM_DISK] = configuration(TEXT("USE_PE_HEADER_FROM_DISK"), configuration::Boolean);
    config[config_option::DEBUG_PRIVILEGE] = configuration(TEXT("DEBUG_PRIVILEGE"), configuration::Boolean);
    config[config_option::CREATE_BACKUP] = configuration(TEXT("CREATE_BACKUP"), configuration::Boolean);
    config[config_option::DLL_INJECTION_AUTO_UNLOAD] = configuration(TEXT("DLL_INJECTION_AUTO_UNLOAD"), configuration::Boolean);
    config[config_option::UPDATE_HEADER_CHECKSUM] = configuration(TEXT("UPDATE_HEADER_CHECKSUM"), configuration::Boolean);
    config[config_option::IAT_SECTION_NAME] = configuration(TEXT("IAT_SECTION_NAME"), configuration::String);
    config[config_option::REMOVE_DOS_HEADER_STUB] = configuration(TEXT("REMOVE_DOS_HEADER_STUB"), configuration::Boolean);
    config[config_option::IAT_FIX_AND_OEP_FIX] = configuration(TEXT("IAT_FIX_AND_OEP_FIX"), configuration::Boolean);
    config[config_option::SUSPEND_PROCESS_FOR_DUMPING] = configuration(TEXT("SUSPEND_PROCESS_FOR_DUMPING"), configuration::Boolean);
    config[config_option::OriginalFirstThunk_SUPPORT] = configuration(TEXT("OriginalFirstThunk_SUPPORT"), configuration::Boolean);
    config[config_option::USE_ADVANCED_IAT_SEARCH] = configuration(TEXT("USE_ADVANCED_IAT_SEARCH"), configuration::Boolean);
    config[config_option::SCAN_DIRECT_IMPORTS] = configuration(TEXT("SCAN_DIRECT_IMPORTS"), configuration::Boolean);
    config[config_option::FIX_DIRECT_IMPORTS_NORMAL] = configuration(TEXT("FIX_DIRECT_IMPORTS_NORMAL"), configuration::Boolean);
    config[config_option::FIX_DIRECT_IMPORTS_UNIVERSAL] = configuration(TEXT("FIX_DIRECT_IMPORTS_UNIVERSAL"), configuration::Boolean);
    config[config_option::CREATE_NEW_IAT_IN_SECTION] = configuration(TEXT("CREATE_NEW_IAT_IN_SECTION"), configuration::Boolean);
    config[config_option::DONT_CREATE_NEW_SECTION] = configuration(TEXT("DONT_CREATE_NEW_SECTION"), configuration::Boolean);
    config[config_option::APIS_ALWAYS_FROM_DISK] = configuration(TEXT("APIS_ALWAYS_FROM_DISK"), configuration::Boolean);
    buildConfigFilePath(fileName);
}

bool configuration_holder::loadConfiguration()
{
    if (_tcslen(configPath) > 0)
    {
        for (auto& mapIter : config)
        {
            configuration& configObject = mapIter.second;
            loadConfig(configObject);
        }
        return true;
    }
    return false;
}

bool configuration_holder::saveConfiguration() const
{
    if (_tcslen(configPath) > 0)
    {
        for (const auto& mapIter : config)
        {
            const configuration& configObject = mapIter.second;
            if (!saveConfig(configObject))
            {
                return false;
            }
        }
        return true;
    }
    return false;
}

configuration& configuration_holder::operator[](config_option option)
{
    return config[option];
}

const configuration& configuration_holder::operator[](config_option option) const
{
    static const configuration dummy;
    
    std::map<config_option, configuration>::const_iterator found = config.find(option);
    if (found != config.end())
    {
        return found->second;
    }
    else
    {
        return dummy;
    }
}

bool configuration_holder::saveNumericToConfigFile(const configuration & configObject, int nBase) const
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

bool configuration_holder::readNumericFromConfigFile(configuration & configObject, int nBase) const
{
    TCHAR buf[21]; // UINT64_MAX in dec has 20 digits
    const DWORD read = GetPrivateProfileString(CONFIG_FILE_SECTION_NAME, configObject.getName(), TEXT(""), buf, _countof(buf), configPath);

    if (read > 0 && _tcslen(buf) > 0)
    {
#ifdef _WIN64
        configObject.setNumeric(_tcstoui64(buf, nullptr, nBase));
#else
        configObject.setNumeric(_tcstoul(buf, nullptr, nBase));
#endif
        return true;
    }

    return false;
}

bool configuration_holder::saveStringToConfigFile(const configuration & configObject) const
{
    const BOOL ret = WritePrivateProfileString(CONFIG_FILE_SECTION_NAME, configObject.getName(), configObject.getString(), configPath);
    return !!ret;
}

bool configuration_holder::readStringFromConfigFile(configuration & configObject) const
{
    TCHAR buf[configuration::CONFIG_STRING_LENGTH];
    const DWORD read = GetPrivateProfileString(CONFIG_FILE_SECTION_NAME, configObject.getName(), TEXT(""), buf, _countof(buf), configPath);
    if (read > 0 && _tcslen(buf) > 0)
    {
        configObject.setString(buf);
        return true;
    }

    return false;
}

bool configuration_holder::readBooleanFromConfigFile(configuration & configObject) const
{
    const UINT val = GetPrivateProfileInt(CONFIG_FILE_SECTION_NAME, configObject.getName(), 0, configPath);
    configObject.setBool(val != 0);
    return true;
}

bool configuration_holder::saveBooleanToConfigFile(const configuration & configObject) const
{
    const TCHAR *boolValue = configObject.isTrue() ? TEXT("1") : TEXT("0");
    const BOOL ret = WritePrivateProfileString(CONFIG_FILE_SECTION_NAME, configObject.getName(), boolValue, configPath);
    return !!ret;
}

bool configuration_holder::loadConfig(configuration & configObject) const
{
    switch (configObject.getType())
    {
    case configuration::String:
        return readStringFromConfigFile(configObject);
    case configuration::Boolean:
        return readBooleanFromConfigFile(configObject);
    case configuration::Decimal:
        return readNumericFromConfigFile(configObject, 10);
    case configuration::Hexadecimal:
        return readNumericFromConfigFile(configObject, 16);
    default:
        return false;
    }
}

bool configuration_holder::saveConfig(const configuration & configObject) const
{
    switch (configObject.getType())
    {
    case configuration::String:
        return saveStringToConfigFile(configObject);
    case configuration::Boolean:
        return saveBooleanToConfigFile(configObject);
    case configuration::Decimal:
        return saveNumericToConfigFile(configObject, 10);
    case configuration::Hexadecimal:
        return saveNumericToConfigFile(configObject, 16);
    default:
        return false;
    }
}

bool configuration_holder::buildConfigFilePath(LPCTSTR fileName)
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
