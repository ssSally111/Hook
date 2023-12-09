#include <Windows.h>
#include <ImageHlp.h>
#include <iostream>
#include "original.h"

#pragma comment(lib, "ImageHlp")
#pragma comment(lib, "original.lib")

BOOL InlineHookX86(PCSTR pszModName, PCSTR pszFnName, PROC pFn);
BOOL InlineHookX64(PCSTR pszModName, PCSTR pszFnName, PROC pFn);
BOOL InlineHookHandle(PROC pFnOld, PROC pFn, BYTE targetBytes[], INT size);
BOOL IATHook(PCSTR pszModName, PCSTR pszFnName, PROC pFn);

BOOL InlineHookX86(PCSTR pszModName, PCSTR pszFnName, PROC pFn)
{
	if (sizeof(int*) << 3 == 32)
	{
		PROC pFnOld = GetProcAddress(GetModuleHandleA(pszModName), pszFnName);
		BYTE targetBytes[]{ 0xE9, 0x00, 0x00, 0x00, 0x00 };
		*(DWORD*)(targetBytes + 1) = (DWORD)pFn - (DWORD)pFnOld - 5;
		return InlineHookHandle(pFnOld, pFn, targetBytes, 5);
	}
	return FALSE;
}

BOOL InlineHookX64(PCSTR pszModName, PCSTR pszFnName, PROC pFn)
{
	if (sizeof(int*) << 3 == 64)
	{
		PROC pFnOld = GetProcAddress(GetModuleHandleA(pszModName), pszFnName);
		BYTE targetBytes[]{ 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
		*(DWORD*)(targetBytes + 2) = (INT64)pFn;
		return InlineHookHandle(pFnOld, pFn, targetBytes, 12);
	}
	return FALSE;
}

BOOL InlineHookHandle(PROC pFnOld, PROC pFn, BYTE targetBytes[], INT size)
{
	SIZE_T dwNum = 0;
	HANDLE hProcess = GetCurrentProcess();
	DWORD dwOldProtect;
	if (!WriteProcessMemory(hProcess, pFnOld, targetBytes, size, &dwNum))
	{
		if (VirtualProtectEx(hProcess, pFnOld, size, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			BOOL bFlag = WriteProcessMemory(hProcess, pFnOld, targetBytes, size, &dwNum);
			VirtualProtectEx(hProcess, pFnOld, size, dwOldProtect, &dwOldProtect);
			return bFlag;
		}
		return FALSE;
	}

	return TRUE;
}

BOOL IATHook(PCSTR pszModName, PCSTR pszFnName, PROC pFn)
{
	HMODULE baseAddr = GetModuleHandle(NULL);
	PROC pFnOld = GetProcAddress(GetModuleHandleA(pszModName), pszFnName);

	ULONG ulSize = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(baseAddr, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize, NULL);
	if (!pImportDesc) return FALSE;

	// dll
	for (; pImportDesc->Name; pImportDesc++)
	{
		PSTR pszMode = (PSTR)((PBYTE)baseAddr + pImportDesc->Name);
		if (!lstrcmpiA(pszModName, pszMode))
		{
			// fn
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)baseAddr + pImportDesc->FirstThunk);
			for (; pThunk->u1.Function; pThunk++)
			{
				PROC* ppfn = (PROC*)&(pThunk->u1.Function);
				if (*ppfn == pFnOld)
				{
					if (!WriteProcessMemory(GetCurrentProcess(), ppfn, &pFn, sizeof(pFn), NULL))
					{
						DWORD dwAttr = 0;
						if (VirtualProtect(ppfn, sizeof(pFn), PAGE_WRITECOPY, &dwAttr))
						{
							BOOL bFlag = WriteProcessMemory(GetCurrentProcess(), ppfn, &pFn, sizeof(pFn), NULL);
							VirtualProtect(ppfn, sizeof(pFn), dwAttr, &dwAttr);
							return bFlag;
						}
						return FALSE;
					}
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

//ԭAPI
//int __stdcall testAdd(int a, int b)
//{
//	return a + b;
//}

int __stdcall callback1(int a, int b)
{
	std::cout << "IAT HOOK callback a:" << a << " b:" << b << std::endl;
	return a - b;
}

int __stdcall callback2(int a, int b)
{
	std::cout << "Inline Hook callback a:" << a << " b:" << b << std::endl;
	return a * b;
}


typedef int(__stdcall* Fn)(int a, int b);

int main(void)
{
	int result1 = testAdd(1, 2);
	std::cout << "Result1:" << result1 << std::endl;

	// IAT HOOK
	//IATHook("original.dll", "testAdd", (PROC)callback1);
	int result2 = testAdd(1, 2);
	std::cout << "IAT HOOK Result2:" << result2 << std::endl;

	// Inline Hook
	//InlineHookX86("original.dll", "testAdd", (PROC)callback2);
	int result3 = testAdd(1, 2);
	std::cout << "Inline HOOK Result3:" << result3 << std::endl;

	return 0;
}