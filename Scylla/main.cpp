//#include <vld.h> // Visual Leak Detector

#include <atlbase.h>       // base ATL classes
#include <atlapp.h>        // base WTL classes
#include <cinttypes>	   // Get correct print formating for integers
#include "Architecture.h"
#include "MainGui.h"
#include "ExceptionHandler.h"

HINSTANCE hDllModule = nullptr;

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	InitCommonControls();
	AddScyllaUnhandledExceptionHandler();
	return InitializeGui(hInstance, (LPARAM)0);
}