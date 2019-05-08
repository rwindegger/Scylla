#include "configuration.h"
#include <tchar.h>

configuration::configuration(LPCTSTR name, Type type)
{
	_tcscpy_s(this->name, name);
	this->type = type;
	valueNumeric = 0;
	valueString[0] = L'\0';
}

LPCTSTR configuration::getName() const
{
	return name;
}

configuration::Type configuration::getType() const
{
	return type;
}

DWORD_PTR configuration::getNumeric() const
{
	return valueNumeric;
}

void configuration::setNumeric(DWORD_PTR value)
{
	valueNumeric = value;
}

LPCTSTR configuration::getString() const
{
	return valueString;
}

void configuration::setString(LPCTSTR str)
{
	_tcsncpy_s(valueString, str, _countof(valueString));
}

bool configuration::getBool() const
{
	return getNumeric() == 1;
}

void configuration::setBool(bool flag)
{
	setNumeric(flag ? 1 : 0);
}

bool configuration::isTrue() const
{
	return getBool();
}

void configuration::setTrue()
{
	setBool(true);
}

void configuration::setFalse()
{
	setBool(false);
}
