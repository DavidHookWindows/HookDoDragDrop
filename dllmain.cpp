// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "easyhook.h"
#include "DriverShared.h"
#include "NtStructDef.h"


#include <time.h>
#include <windows.h>


EASYHOOK_BOOL_EXPORT EasyHookDllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

typedef HRESULT(__stdcall * pfnDoDragDrop)
(
	LPDATAOBJECT pDataObj,
	LPDROPSOURCE pDropSource,
	DWORD dwOKEffects,
	LPDWORD pdwEffect
	);

pfnDoDragDrop			pfnOrgDoDragDrop = NULL;
TRACED_HOOK_HANDLE      hHookDoDragDrop = new HOOK_TRACE_INFO();
ULONG                   HookDoDragDrop_ACLEntries[1] = { 0 };


static ULONG_PTR _stdcall  DoDragDropHook(
	LPDATAOBJECT pDataObj,
	LPDROPSOURCE pDropSource,
	DWORD dwOKEffects,
	LPDWORD pdwEffect
)
{
	return DRAGDROP_S_CANCEL;
}


TCHAR					szCurrentProcessName[MAX_PATH] = { 0 };
DWORD					dwCurrentProcessId;



void ReadReg(WCHAR* hsRet)
{
	LONG status = ERROR_SUCCESS;
	HKEY hSubKey = NULL;

	do
	{
		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\ACPI", 0, KEY_READ, &hSubKey);
		if (ERROR_SUCCESS != status)
		{
			break;
		}

		DWORD dwType;
		WCHAR wszPath[MAX_PATH] = { 0 };
		DWORD dwByteLen = MAX_PATH * sizeof(WCHAR);

		status = RegQueryValueExW(hSubKey, L"Control", NULL, &dwType, (LPBYTE)wszPath, &dwByteLen);
		if (ERROR_SUCCESS != status)
		{
			break;
		}
		StrCpyNW(hsRet, wszPath, dwByteLen);
	} while (false);

}





BOOL InstallHook()
{

	NTSTATUS ntStatus;


	if (NULL != pfnOrgDoDragDrop)
	{
		ntStatus = LhInstallHook(pfnOrgDoDragDrop, DoDragDropHook, NULL, hHookDoDragDrop);
		if (!SUCCEEDED(ntStatus))
		{
			OutputDebugString(_T("LhInstallHook DoDragDropHook failed..\n"));
			return FALSE;
		}

		ntStatus = LhSetExclusiveACL(HookDoDragDrop_ACLEntries, 1, hHookDoDragDrop);
		if (!SUCCEEDED(ntStatus))
		{
			OutputDebugString(_T("LhSetInclusiveACL HookDoDragDrop_ACLEntries failed..\n"));
			return FALSE;
		}
	}
	
	return TRUE;
}

BOOL UnInstallHook()
{
	LhUninstallAllHooks();

	if (NULL != hHookDoDragDrop)
	{
		LhUninstallHook(hHookDoDragDrop);
		delete hHookDoDragDrop;
		hHookDoDragDrop = NULL;
	}



	LhWaitForPendingRemovals();

	return TRUE;
}

DWORD WINAPI HookThreadProc(LPVOID lpParamter)
{

	HMODULE h2 = GetModuleHandle(_T("ole32.dll"));
	if (h2 == 0)
		h2 = LoadLibraryA("ole32.dll");
	if(h2)
		pfnOrgDoDragDrop = (pfnDoDragDrop)GetProcAddress(h2, "DoDragDrop");
	if (pfnOrgDoDragDrop)
	{
		InstallHook();
	}
	
	return 0;
}






void StartHookThread()
{
	WCHAR hsFUnc[MAX_PATH] = { 0 };
	ReadReg(hsFUnc);
	if (_wcsicmp(hsFUnc, L"NoRsp") == 0)
	{
		DWORD dwThreadID = 0;
		HANDLE hThread = CreateThread(NULL, 0, HookThreadProc, NULL, 0, &dwThreadID);
		if (hThread == INVALID_HANDLE_VALUE)
		{
			OutputDebugStringA("HookThreadProc falied");
		}
		CloseHandle(hThread);
	}
	
}




BOOL APIENTRY DllMain(HINSTANCE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	EasyHookDllMain(hModule, ul_reason_for_call, lpReserved);


	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
	
		wchar_t szTmp[514] = { 0 };
		::GetModuleFileNameW(NULL, szTmp, 512);
		_wcslwr_s(szTmp);//转小写
		OutputDebugStringW(szTmp);

		//if (wcsstr(szTmp, L"a.exe") != NULL || wcsstr(szTmp, L"b.exe") != NULL)
			StartHookThread();
	}
	break;
	case DLL_THREAD_ATTACH:
		
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		UnInstallHook();
	}
	break;
	}
	return TRUE;
}

