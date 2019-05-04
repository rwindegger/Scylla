#pragma once

#include <windows.h>

class Configuration
{
public:

	enum Type {
		String,
		Decimal,
		Hexadecimal,
		Boolean
	};

	static const size_t CONFIG_NAME_LENGTH = 100;
	static const size_t CONFIG_STRING_LENGTH = 100;

	Configuration(LPCTSTR name = TEXT(""), Type type = String);

    LPCTSTR getName() const;
	Type getType() const;

	DWORD_PTR getNumeric() const;
	void setNumeric(DWORD_PTR value);

    LPCTSTR getString() const;
	void setString(LPCTSTR str);

	bool getBool() const;
	void setBool(bool flag);

	// Redundant (we have getBool and setBool), but easier on the eye
	bool isTrue() const;
	void setTrue();
	void setFalse();

private:

	TCHAR name[CONFIG_NAME_LENGTH]{};
	Type type;

	DWORD_PTR valueNumeric;
	TCHAR valueString[CONFIG_STRING_LENGTH]{};
};
