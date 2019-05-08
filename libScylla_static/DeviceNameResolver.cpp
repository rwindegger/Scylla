#include "StringConversion.h"
#include "DeviceNameResolver.h"
#include "libscylla.h"
#include "native_win_api.h"

DeviceNameResolver::DeviceNameResolver()
{
    initDeviceNameList();
}

DeviceNameResolver::~DeviceNameResolver()
{
    deviceNameList.clear();
}

void DeviceNameResolver::initDeviceNameList()
{
    TCHAR shortName[3]{};
    TCHAR longName[MAX_PATH]{};
    HardDisk hardDisk{};

    shortName[1] = TEXT(':');

    deviceNameList.reserve(3);

    for (TCHAR shortD = TEXT('a'); shortD <= TEXT('z'); shortD++)
    {
        shortName[0] = shortD;
        if (QueryDosDevice(shortName, longName, MAX_PATH) > 0)
        {
            hardDisk.shortName[0] = _totupper(shortD);
            hardDisk.shortName[1] = TEXT(':');
            hardDisk.shortName[2] = 0;

            hardDisk.longNameLength = _tcslen(longName);

            _tcscpy_s(hardDisk.longName, _countof(hardDisk.longName), longName);
            deviceNameList.push_back(hardDisk);
        }
    }

    fixVirtualDevices();
}

bool DeviceNameResolver::resolveDeviceLongNameToShort(LPCTSTR sourcePath, LPTSTR targetPath)
{
    for (auto& i : deviceNameList)
    {
        if (!_tcsnicmp(i.longName, sourcePath, i.longNameLength) && sourcePath[i.longNameLength] == TEXT('\\'))
        {
            _tcscpy_s(targetPath, MAX_PATH, i.shortName);

            _tcscat_s(targetPath, MAX_PATH, sourcePath + i.longNameLength);
            return true;
        }
    }

    return false;
}

void DeviceNameResolver::fixVirtualDevices()
{
    const USHORT BufferSize = MAX_PATH * 2 * sizeof(WCHAR);
    WCHAR longCopy[MAX_PATH] = { 0 };
    OBJECT_ATTRIBUTES oa{};
    UNICODE_STRING unicodeInput{};
    UNICODE_STRING unicodeOutput{};
    HANDLE hFile = nullptr;
    ULONG retLen = 0;
    HardDisk hardDisk{};

    unicodeOutput.Buffer = static_cast<PWSTR>(malloc(BufferSize));
    if (!unicodeOutput.Buffer)
        return;

    for (unsigned int i = 0; i < deviceNameList.size(); i++)
    {
        StringConversion::ToWStr(deviceNameList[i].longName, longCopy, MAX_PATH);
        libscylla::windows_api()->RtlInitUnicodeString(&unicodeInput, longCopy);
        InitializeObjectAttributes(&oa, &unicodeInput, 0, NULL, NULL);

        if (NT_SUCCESS(libscylla::windows_api()->NtOpenSymbolicLinkObject(&hFile, SYMBOLIC_LINK_QUERY, &oa)))
        {
            unicodeOutput.Length = BufferSize;
            unicodeOutput.MaximumLength = unicodeOutput.Length;
            ZeroMemory(unicodeOutput.Buffer, unicodeOutput.Length);

            if (NT_SUCCESS(libscylla::windows_api()->NtQuerySymbolicLinkObject(hFile, &unicodeOutput, &retLen)))
            {
                hardDisk.longNameLength = wcslen(unicodeOutput.Buffer);
                _tcscpy_s(hardDisk.shortName, deviceNameList[i].shortName);
                StringConversion::ToTStr(unicodeOutput.Buffer, hardDisk.longName, MAX_PATH);
                deviceNameList.push_back(hardDisk);
            }

            libscylla::windows_api()->NtClose(hFile);
        }
    }

    free(unicodeOutput.Buffer);
}

