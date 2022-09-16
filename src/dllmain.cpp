#include "utils.h"
//#include "debugger.h" //#akebi-contributors
#include <assert.h>

static uint64_t UnityPlayer = reinterpret_cast<uint64_t>(GetModuleHandleA("UnityPlayer.dll"));

// Thanks khang06
int RecordChecksumUserData_Hook(int type, char* out, int out_size)
{
	auto ret = CALL_ORIGIN(RecordChecksumUserData_Hook, type, out, out_size);
	Utils::ConsolePrint("RecordChecksumUserData with type %d and ret %d: %s\n", type, ret, out);
	const char* data[] = {
		"c071e821a011fe7a5f6c791d4002dc4b2",
		"ed2e864481c6fe2e9db3b6379c18f6b25",
		"",
		""
	};
	assert(type < sizeof(data) / sizeof(const char*));
	ret = strlen(data[type]);
	if (strcmp(data[type], out) != 0)
		Utils::ConsolePrint("Hash mismatch, but required!\n");
	strncpy(out, data[type], out_size);

	return ret;
}

void ChecksumBypass()
{
#define ResolvePattern(instruction, sig) Resolve::##instruction(UnityPlayer, Utils::PatternScan(UnityPlayer, sig))
	//auto ChecksumUserData = (int(*)(int, char*, int))(ResolvePattern(JMP, "e8 ? ? ? ? 48 8b 4c 24 ? 89 01 48 8b 8c 24 ? ? ? ? 48 31 e1 e8 ? ? ? ? 48 81 c4 ? ? ? ? 5b"));
	auto RecordChecksumUserData = (int(*)(int, char*, int))(Utils::PatternScan(UnityPlayer, "55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec ? ? ? ? 48 8d ac 24 ? ? ? ? 44 89 45 ? 48 89 55 ? 89 4d"));
#undef ResolvePattern

	HookManager::install(RecordChecksumUserData, RecordChecksumUserData_Hook);
}

DWORD WINAPI Thread(LPVOID p)
{
	//Utils::AttachConsole();
	//DebuggerBypassPre();
	//DebuggerBypassPost();

	while (true)
	{
		while (!(GetModuleHandleA("UnityPlayer.dll")))
			Sleep(1000);

		ChecksumBypass();
		Utils::CloseDriverHandleName(L"\\Device\\mhyprot2");

		Sleep(5000);
	}

	//Utils::DetachConsole();
	FreeLibraryAndExitThread((HMODULE)p, 0);
	return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Thread, hModule, 0, nullptr));
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}