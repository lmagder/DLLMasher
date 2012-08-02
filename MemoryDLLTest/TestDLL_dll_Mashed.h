extern "C"
{
BOOL WINAPI TestDLL_dll_DllMain(
	__in  HINSTANCE hinstDLL,
	__in  DWORD fdwReason,
	__in  LPVOID lpvReserved
	);
}

inline void TestDLL_dll_FakeLoadLibrary() { TestDLL_dll_DllMain(GetModuleHandle(0), DLL_PROCESS_ATTACH, 0); }
inline void TestDLL_dll_FakeFreeLibrary() { TestDLL_dll_DllMain(GetModuleHandle(0), DLL_PROCESS_DETACH, 0); }

