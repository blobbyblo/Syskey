#include <Windows.h>
#include <iostream>

#include "Syskey.h"

DWORD __stdcall MainThread(LPVOID lpParam)
{
	FILE* pfStream = nullptr;

	// Allocate a console window and prepare for output
	AllocConsole();
	freopen_s(&pfStream, "CONOUT$", "w", stdout);
	freopen_s(&pfStream, "CONOUT$", "w", stderr);

	while (!(nt::GetKey(VK_F5) & 0x8000))
	{
		printf("Press F5 to exit the loop.\n");
	}
	printf("Done! Goodbye\n");

	// Free the console window to allow closing
	FreeConsole();

	return 0;
}

bool bCallOnce = false;
bool __stdcall DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved)
{
	if (!bCallOnce)
	{
		bCallOnce = true;
		if (ulReason == DLL_PROCESS_ATTACH)
		{
			CreateThread(nullptr, 0, MainThread, 0, 0, nullptr);
		}
	}
	return true;
}
