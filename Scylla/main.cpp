//#include <vld.h> // Visual Leak Detector

#include <atlbase.h>       // base ATL classes
#include <atlapp.h>        // base WTL classes
#include <inttypes.h>	   // Get correct print formating for integers
#include "Architecture.h"
#include "MainGui.h"
#include "ExceptionHandler.h"
#include "Scylla.h"
#include "MainGui.h"

HINSTANCE hDllModule = 0;
bool IsDllMode = false;



int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	InitCommonControls();
	AddScyllaUnhandledExceptionHandler();
	IsDllMode = false;
	return InitializeGui(hInstance, (LPARAM)0);
}