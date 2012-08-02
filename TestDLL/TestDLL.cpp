// TestDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "TestDLL.h"

#include <vector>
#include <string>

// This is an example of an exported variable
TESTDLL_API int nTestDLL=0;

// This is an example of an exported function.
TESTDLL_API int fnTestDLL(void)
{
  printf("(in dll)\n");
  std::vector<std::string> t;
  t.push_back("MessageBox Message");
  t.push_back("MessageBox Caption!");
  MessageBoxA(0, t[0].c_str(), t[1].c_str(), 0);
	return 42;
}

// This is the constructor of a class that has been exported.
// see TestDLL.h for the class definition
CTestDLL::CTestDLL()
{
	return;
}
