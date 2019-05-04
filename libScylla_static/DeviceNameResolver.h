#pragma once

#include <Windows.h>
#include <vector>

class HardDisk {
public:
	TCHAR shortName[3];
	TCHAR longName[MAX_PATH];
	size_t longNameLength;
};

class DeviceNameResolver
{
public:
	DeviceNameResolver();
	~DeviceNameResolver();
	bool resolveDeviceLongNameToShort(LPCTSTR sourcePath, LPTSTR targetPath);
private:
	std::vector<HardDisk> deviceNameList;

	void initDeviceNameList();
    void fixVirtualDevices();
};
