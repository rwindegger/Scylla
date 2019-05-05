#include <windows.h>
#include "Scylla.h"
#include "ExceptionHandler.h"

HINSTANCE hDllModule = nullptr;

ConsoleLogger logger;

void InitializeDll(HINSTANCE hinstDLL)
{
	hDllModule = hinstDLL;
	Scylla::initialize(&logger, false);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	// Perform actions based on the reason for calling.
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		AddScyllaUnhandledExceptionHandler();
		InitializeDll(hinstDLL);
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		RemoveScyllaUnhandledExceptionHandler();
		break;
	default: ;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
