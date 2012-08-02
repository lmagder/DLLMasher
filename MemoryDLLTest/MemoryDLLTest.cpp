// MemoryDLLTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "TestDLL_dll_Mashed.h"

int _tmain(int argc, _TCHAR* argv[])
{
  std::string foo("foo");
  TestDLL_dll_FakeLoadLibrary();

  MessageBoxEx(0, TEXT("MessageBox Message"), TEXT("MessageBox Caption!"), 0, 0);
  //__pfnDliNotifyHook2 = &MyHook;
  printf("Init...\n");
  fnTestDLL();
  printf("After...\n");
  fnTestDLL();
  printf("After2...\n");

  TestDLL_dll_FakeFreeLibrary();
	return 0;
}

