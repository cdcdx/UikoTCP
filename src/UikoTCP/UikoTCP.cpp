//************************************************************
//  UikoTCP - NSIS TCP Library
//
//  File: tcp.cpp
//  Version: 2.0.0.2001
//  CreateDate: 2013-01-04
//  LastDate: 2014-09-03
//
//  Author: Garfield
//
//  Copyright (c) 2012-2015, Uiko Develop Team.
//  All Rights Reserved.
//************************************************************

#include <windows.h>
#include <winsock.h>
#include <string>
#include <io.h>

//#include "exdll.h"
#include "pluginapi.h"
//#include "precomp.h"

//Uiko Core
//#include "core.h"
#include <atlstr.h>
// Find Process
#include <tlhelp32.h>
#include <ipexport.h>
#include <IcmpApi.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
//下载
#include <WinInet.h>
#pragma comment( lib, "wininet.lib")
#pragma comment( lib, "ws2_32.lib")
//任务栏图标
#include <shlobj.h>
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"advapi32.lib")

#pragma warning( disable : 4996 )

using namespace std;

#define nullptr (HMODULE)0

HMODULE g_hModule = nullptr;

//NSIS回调
extern HINSTANCE  g_hInstance;

// wchar_t* -> string
std::string wchar2string( const wchar_t* pwchar )
{
    int nLen = WideCharToMultiByte(CP_ACP, 0, pwchar, -1, NULL, 0, NULL, NULL);
    if (nLen<= 0) return std::string("");
    char* pszDst = new char[nLen];
    if (NULL == pszDst) return std::string("");
    WideCharToMultiByte(CP_ACP, 0, pwchar, -1, pszDst, nLen, NULL, NULL);
    pszDst[nLen -1] = 0;
    std::string strTemp(pszDst);
    delete [] pszDst;
    return strTemp;
}
// char* -> wstring
std::wstring char2wstring( const char* pchar , int nLen)
{
    int nSize = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)pchar, nLen, 0, 0);
    if(nSize <= 0) return NULL;
    WCHAR *pwszDst = new WCHAR[nSize+1];
    if( NULL == pwszDst) return NULL;
    MultiByteToWideChar(CP_ACP, 0,(LPCSTR)pchar, nLen, pwszDst, nSize);
    pwszDst[nSize] = 0;
    if( pwszDst[0] == 0xFEFF) // skip Oxfeff
        for(int i = 0; i < nSize; i ++) 
            pwszDst[i] = pwszDst[i+1];
    std::wstring wcharString(pwszDst);
    delete pwszDst;
    return wcharString;
}

// check if the socket on the stack is free for binding on localhost
extern "C" void __declspec(dllexport) CheckPort(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	// setup nsis environment

    EXDLL_INIT();
    //g_pluginParms = extra;
    //EXDLL_INIT();
    //extra->RegisterPluginCallback( g_hInstance, PluginCallback );
    
	//Uiko Core
	//Init(0);

	// get and parse port number
	TCHAR ports[11];
	popstringn(ports,10);
    //int port = atoi(ports);
#if _UNICODE
    int port = _wtoi(ports);
#else
    int port = atoi(ports);
#endif
	
	if (port <= 0 || port > 65536)
	{
		pushstring(_T("socket_error"));
		return;
	}

	// start winsock
	WSADATA wsa_data;
	WORD req_version = MAKEWORD(1,1);
	if (WSAStartup(req_version, &wsa_data) != 0) {
		pushstring(_T("winsock_error"));
		return;
	}

	// create and bind a socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
	{
		pushstring(_T("socket_error"));
		return;
	}

	struct sockaddr_in server = {0};
	server.sin_port = htons((unsigned short)port);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	if (bind(sock, (struct sockaddr *)&server, sizeof server) == SOCKET_ERROR)
	{
		if (GetLastError() == WSAEADDRINUSE)
		{
			closesocket(sock);
			WSACleanup();
			pushstring(_T("inuse"));
			return;
		}

		closesocket(sock);
		WSACleanup();
		pushstring(_T("bind_error"));
		return;
	}
	closesocket(sock);
	WSACleanup();
	pushstring(_T("free"));
	return;
}


// check if the url online state
int GetOnlineState(char *websiteName)
{

	/////////////////////判断联网代码/////////////////////////////////////////////////////
	WORD wVersionRequested = MAKEWORD( 2, 2 );
	WSADATA wsaData;
	int err = WSAStartup( wVersionRequested, &wsaData );

	if( websiteName==NULL )
	{
		return 0;
	}
	//////////////////////////////////////////////////////////////////
	string asWebSite("");
	string asDstIp("");

	asWebSite = websiteName;

	HOSTENT *host = ::gethostbyname(asWebSite.c_str());
	if (NULL != host)
	{
		sockaddr_in sa;
		for (int nAdapter=0; host->h_addr_list[nAdapter]; nAdapter++)
		{
			memcpy ( &sa.sin_addr.s_addr, host->h_addr_list[nAdapter],host->h_length);
			asDstIp = inet_ntoa(sa.sin_addr);
		}
	}
	else
	{
		return 0;
	}

	HANDLE hIcmpFile;
	unsigned long ipaddr = INADDR_NONE;
	DWORD dwRetVal = 0;
	char SendData[] = "Data Buffer";
	LPVOID ReplyBuffer = NULL;
	DWORD ReplySize = 0;

	// Validate the parameters
	ipaddr = inet_addr(asDstIp.c_str());
	if (ipaddr == INADDR_NONE)
	{
		return 0;
	}

	hIcmpFile = IcmpCreateFile();
	if (hIcmpFile == INVALID_HANDLE_VALUE)
	{
		return 0;
	}    

	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
	ReplyBuffer = (VOID*) malloc(ReplySize);
	if (ReplyBuffer == NULL) 
	{
		return 0;
	}

	dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData), 
		NULL, ReplyBuffer, ReplySize, 1000);
	PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
	if (dwRetVal != 0) 
	{ 
		PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
		char* p  = (char*)(pEchoReply->Data);
		struct in_addr ReplyAddr;
		ReplyAddr.S_un.S_addr = pEchoReply->Address;

		return 200;
	}
	else 
	{
		return 0;
	}

	//////////////////////////////////////////////////////////////////
}
extern "C" void __declspec(dllexport) CheckURL(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra)
{
	// setup nsis environment
	EXDLL_INIT();

	//Uiko Core
	//Init(0);

	TCHAR websiteName[MAX_PATH];
	ZeroMemory( websiteName, MAX_PATH );
	popstring( websiteName );

	if (websiteName == NULL)
	{
		//strcpy_s(websiteName, 16, _T("www.baidu.com") );
#if _UNICODE
        wcscpy_s(websiteName, 16, _T("www.baidu.com") );
#else
        strcpy_s(websiteName, 16, _T("www.baidu.com") );
#endif
	}

	int onlinestate = 0;
#if _UNICODE
	onlinestate = GetOnlineState((char*)websiteName);
#else
	onlinestate = GetOnlineState(websiteName);
#endif

	pushint( onlinestate );
	return;
}

// Find Process
int FindProcByName(TCHAR *szToFind)
{
	BOOL bResult,bResultm;
	DWORD aiPID[1000],iCb=1000,iNumProc,iV2000=0;
	DWORD iCbneeded,i;
    TCHAR szName[MAX_PATH],szToTermUpper[MAX_PATH];
    ZeroMemory(szName, MAX_PATH);
    ZeroMemory(szToTermUpper, MAX_PATH);
	HANDLE hProc,hSnapShot,hSnapShotm;
	OSVERSIONINFO osvi;
	HINSTANCE hInstLib;
	int iLen,iLenP,indx;
	HMODULE hMod;
	PROCESSENTRY32 procentry;
	MODULEENTRY32 modentry;

	// PSAPI Function Pointers.
	BOOL (WINAPI *lpfEnumProcesses)( DWORD *, DWORD cb, DWORD * );
	BOOL (WINAPI *lpfEnumProcessModules)( HANDLE, HMODULE *, DWORD, LPDWORD );
	DWORD (WINAPI *lpfGetModuleBaseName)( HANDLE, HMODULE, LPTSTR, DWORD );

	// ToolHelp Function Pointers.
	HANDLE (WINAPI *lpfCreateToolhelp32Snapshot)(DWORD,DWORD) ;
	BOOL (WINAPI *lpfProcess32First)(HANDLE,LPPROCESSENTRY32) ;
	BOOL (WINAPI *lpfProcess32Next)(HANDLE,LPPROCESSENTRY32) ;
	BOOL (WINAPI *lpfModule32First)(HANDLE,LPMODULEENTRY32) ;
	BOOL (WINAPI *lpfModule32Next)(HANDLE,LPMODULEENTRY32) ;

	// Transfer Process name into "szToTermUpper" and
	// convert it to upper case
    //iLenP = strlen(szToFind);
#ifdef UNICODE
    iLenP = wcslen(szToFind);
#else
    iLenP = strlen(szToFind);
#endif

	if( iLenP<1 || iLenP>MAX_PATH ) return 632;
	for(indx=0; indx<iLenP; indx++)
		szToTermUpper[indx] = toupper(szToFind[indx]);
	szToTermUpper[iLenP] = 0;

	// First check what version of Windows we're in
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	bResult = GetVersionEx(&osvi);
	if(!bResult)     // Unable to identify system version
		return 606;

	// At Present we only support Win/NT/2000/XP or Win/9x/ME
	if((osvi.dwPlatformId != VER_PLATFORM_WIN32_NT) && (osvi.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS))
		return 607;

	if(osvi.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		// Win/NT or 2000 or XP

		// Load library and get the procedures explicitly. We do
		// this so that we don't have to worry about modules using
		// this code failing to load under Windows 9x, because
		// it can't resolve references to the PSAPI.DLL.
		
		hInstLib = LoadLibrary(_T("PSAPI.DLL"));
		if(hInstLib == NULL)
			return 605;

		// Get procedure addresses.
		lpfEnumProcesses = (BOOL(WINAPI *)(DWORD *,DWORD,DWORD*)) GetProcAddress( hInstLib, "EnumProcesses" ) ;
		lpfEnumProcessModules = (BOOL(WINAPI *)(HANDLE, HMODULE *, DWORD, LPDWORD)) GetProcAddress( hInstLib, "EnumProcessModules" ) ;
#ifdef _UNICODE
        lpfGetModuleBaseName =(DWORD (WINAPI *)(HANDLE, HMODULE, LPTSTR, DWORD )) GetProcAddress( hInstLib, "GetModuleBaseNameW" ) ;
#else
        lpfGetModuleBaseName =(DWORD (WINAPI *)(HANDLE, HMODULE, LPTSTR, DWORD )) GetProcAddress( hInstLib, "GetModuleBaseNameA" ) ;
#endif


		if( lpfEnumProcesses == NULL || lpfEnumProcessModules == NULL || lpfGetModuleBaseName == NULL )
		{
			FreeLibrary(hInstLib);
			return 605;
		}

		bResult = lpfEnumProcesses( aiPID, iCb, &iCbneeded );
		if(!bResult)
		{
			// Unable to get process list, EnumProcesses failed
			FreeLibrary( hInstLib );
			return 605;
		}

		// How many processes are there?
		iNumProc = iCbneeded/sizeof(DWORD);

		// Get and match the name of each process
		for(i=0; i<iNumProc; i++)
		{
			// Get the (module) name for this process
			
			//strcpy_s(szName,"Unknown");
#if _UNICODE
            wcscpy_s(szName,_T("Unknown"));
#else
            strcpy_s(szName,_T("Unknown"));
#endif

			// First, get a handle to the process
			hProc = OpenProcess( PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, aiPID[i] );
			// Now, get the process name
			if(hProc)
			{
				if( lpfEnumProcessModules(hProc, &hMod, sizeof(hMod), &iCbneeded) )
				{
					iLen = lpfGetModuleBaseName( hProc, hMod, szName, MAX_PATH );
				}
			}
			CloseHandle(hProc);
			// We will match regardless of lower or upper case
#ifdef BORLANDC
			if(strcmp(strupr(szName),szToTermUpper) == 0)
#else
            //if(strcmp(_strupr_s(szName),szToTermUpper) == 0)
            //if(strcmp(_strupr(szName),szToTermUpper) == 0)
    #ifdef _UNICODE
            if(wcscmp(_wcsupr(szName), szToTermUpper ) == 0)
    #else
            if(strcmp(_strupr(szName), szToTermUpper ) == 0)
    #endif
#endif
			{
				// Process found
				FreeLibrary( hInstLib );
				return 1;
			}
		}
	}

	if( osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )
	{
		// Win/95 or 98 or ME
		hInstLib = LoadLibrary(_T("Kernel32.DLL"));
		if( hInstLib == NULL )
			return 605;

		// Get procedure addresses.
		// We are linking to these functions of Kernel32
		// explicitly, because otherwise a module using
		// this code would fail to load under Windows NT,
		// which does not have the Toolhelp32
		// functions in the Kernel 32.
		lpfCreateToolhelp32Snapshot = (HANDLE(WINAPI *)(DWORD,DWORD)) GetProcAddress( hInstLib, "CreateToolhelp32Snapshot" ) ;
		lpfProcess32First = (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32)) GetProcAddress( hInstLib, "Process32First" ) ;
		lpfProcess32Next = (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32)) GetProcAddress( hInstLib, "Process32Next" ) ;
		lpfModule32First = (BOOL(WINAPI *)(HANDLE,LPMODULEENTRY32)) GetProcAddress( hInstLib, "Module32First" ) ;
		lpfModule32Next = (BOOL(WINAPI *)(HANDLE,LPMODULEENTRY32)) GetProcAddress( hInstLib, "Module32Next" ) ;
		if( lpfProcess32Next == NULL ||
			lpfProcess32First == NULL ||
			lpfModule32Next == NULL ||
			lpfModule32First == NULL ||
			lpfCreateToolhelp32Snapshot == NULL )
		{
			FreeLibrary(hInstLib);
			return 605;
		}

		// The Process32.. and Module32.. routines return names in all uppercase

		// Get a handle to a Toolhelp snapshot of all the systems processes.

		hSnapShot = lpfCreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) ;
		if( hSnapShot == INVALID_HANDLE_VALUE )
		{
			FreeLibrary(hInstLib);
			return 605;
		}

		// Get the first process' information.
		procentry.dwSize = sizeof(PROCESSENTRY32);
		bResult = lpfProcess32First( hSnapShot, &procentry );

		// While there are processes, keep looping and checking.
		while(bResult)
		{
			// Get a handle to a Toolhelp snapshot of this process.
			hSnapShotm = lpfCreateToolhelp32Snapshot( TH32CS_SNAPMODULE, procentry.th32ProcessID ) ;
			if( hSnapShotm == INVALID_HANDLE_VALUE )
			{
				CloseHandle(hSnapShot);
				FreeLibrary(hInstLib);
				return 605;
			}
			// Get the module list for this process
			modentry.dwSize = sizeof(MODULEENTRY32);
			bResultm = lpfModule32First( hSnapShotm, &modentry );

			// While there are modules, keep looping and checking
			while(bResultm)
			{

            //if(strcmp(modentry.szModule, szToTermUpper)==0)
#ifdef _UNICODE
                if(wcscmp(modentry.szModule, szToTermUpper) == 0)
#else
                if(strcmp(modentry.szModule, szToTermUpper) == 0)
#endif
				{
					// Process found
					CloseHandle(hSnapShotm);
					CloseHandle(hSnapShot);
					FreeLibrary(hInstLib);
					return 1;
				}
				else
				{  // Look for next modules for this process
					modentry.dwSize = sizeof(MODULEENTRY32);
					bResultm = lpfModule32Next(hSnapShotm, &modentry);
				}
			}

			//Keep looking
			CloseHandle(hSnapShotm);
			procentry.dwSize = sizeof(PROCESSENTRY32);
			bResult = lpfProcess32Next(hSnapShot,&procentry);
		}
		CloseHandle(hSnapShot);
	}
	FreeLibrary(hInstLib);
	return 0;
}
// 查找进程
extern "C" void __declspec(dllexport) FindProcess(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	TCHAR parameter[MAX_PATH];
	ZeroMemory( parameter, MAX_PATH );
	int value = 0;

	EXDLL_INIT();
	{
		popstring(parameter);
		
		value = FindProcByName(parameter);
		//wsprintf(parameter,"%d",value);
#ifdef UNICODE
        wsprintf(parameter, _T("%d"), value);
#else
        sprintf_s(parameter, "%d", value);
#endif
		
		setuservariable(INST_R0, parameter);
	}
}

// Kill Process
int KillProcessFromName(TCHAR *szToTerminate)
// Created: 6/23/2000  (RK)
// Last modified: 3/10/2002  (RK)
// Please report any problems or bugs to kochhar@physiology.wisc.edu
// The latest version of this routine can be found at:
//     http://www.neurophys.wisc.edu/ravi/software/killproc/
// Terminate the process "szToTerminate" if it is currently running
// This works for Win/95/98/ME and also Win/NT/2000/XP
// The process name is case-insensitive, i.e. "notepad.exe" and "NOTEPAD.EXE"
// will both work (for szToTerminate)
// Return codes are as follows:
//   0   = Process was successfully terminated
//   603 = Process was not currently running
//   604 = No permission to terminate process
//   605 = Unable to load PSAPI.DLL
//   602 = Unable to terminate process for some other reason
//   606 = Unable to identify system type
//   607 = Unsupported OS
//   632 = Invalid process name
//   700 = Unable to get procedure address from PSAPI.DLL
//   701 = Unable to get process list, EnumProcesses failed
//   702 = Unable to load KERNEL32.DLL
//   703 = Unable to get procedure address from KERNEL32.DLL
//   704 = CreateToolhelp32Snapshot failed
// Change history:
//   modified 3/8/2002  - Borland-C compatible if BORLANDC is defined as
//                        suggested by Bob Christensen
//   modified 3/10/2002 - Removed memory leaks as suggested by
//					      Jonathan Richard-Brochu (handles to Proc and Snapshot
//                        were not getting closed properly in some cases)
{
	BOOL bResult,bResultm;
	DWORD aiPID[1000], iCb=1000, iNumProc, iV2000=0;
	DWORD iCbneeded, i, iFound=0;
    TCHAR szName[MAX_PATH],szToTermUpper[MAX_PATH];
    ZeroMemory(szName, MAX_PATH);
    ZeroMemory(szToTermUpper, MAX_PATH);
	HANDLE hProc,hSnapShot,hSnapShotm;
	OSVERSIONINFO osvi;
    HINSTANCE hInstLib;
	int iLen,iLenP,indx;
    HMODULE hMod;
	PROCESSENTRY32 procentry;      
	MODULEENTRY32 modentry;

	// Transfer Process name into "szToTermUpper" and
	// convert it to upper case
    //iLenP = strlen(szToTerminate);
#ifdef UNICODE
    iLenP = wcslen(szToTerminate);
#else
    iLenP = strlen(szToTerminate);
#endif

	if(iLenP<1 || iLenP>MAX_PATH) return 632;
	for(indx = 0; indx<iLenP; indx++)
		szToTermUpper[indx] = toupper(szToTerminate[indx]);
	szToTermUpper[iLenP] = 0;

    // PSAPI Function Pointers.
    BOOL (WINAPI *lpfEnumProcesses)( DWORD *, DWORD cb, DWORD * );
    BOOL (WINAPI *lpfEnumProcessModules)( HANDLE, HMODULE *, DWORD, LPDWORD );
    DWORD (WINAPI *lpfGetModuleBaseName)( HANDLE, HMODULE, LPTSTR, DWORD );

    // ToolHelp Function Pointers.
    HANDLE (WINAPI *lpfCreateToolhelp32Snapshot)(DWORD,DWORD) ;
    BOOL (WINAPI *lpfProcess32First)(HANDLE,LPPROCESSENTRY32) ;
    BOOL (WINAPI *lpfProcess32Next)(HANDLE,LPPROCESSENTRY32) ;
    BOOL (WINAPI *lpfModule32First)(HANDLE,LPMODULEENTRY32) ;
    BOOL (WINAPI *lpfModule32Next)(HANDLE,LPMODULEENTRY32) ;

	// First check what version of Windows we're in
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    bResult=GetVersionEx(&osvi);
	if(!bResult)     // Unable to identify system version
	    return 606;

	// At Present we only support Win/NT/2000/XP or Win/9x/ME
	if((osvi.dwPlatformId != VER_PLATFORM_WIN32_NT) && (osvi.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS))
		return 607;

    if(osvi.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		// Win/NT or 2000 or XP

        // Load library and get the procedures explicitly. We do
        // this so that we don't have to worry about modules using
        // this code failing to load under Windows 9x, because
        // it can't resolve references to the PSAPI.DLL.
        hInstLib = LoadLibrary(_T("PSAPI.DLL"));
        if(hInstLib == NULL)
            return 605;

        // Get procedure addresses.
        lpfEnumProcesses = (BOOL(WINAPI *)(DWORD *,DWORD,DWORD*)) GetProcAddress( hInstLib, "EnumProcesses" ) ;
        lpfEnumProcessModules = (BOOL(WINAPI *)(HANDLE, HMODULE *, DWORD, LPDWORD)) GetProcAddress( hInstLib, "EnumProcessModules" ) ;
#ifdef _UNICODE
        lpfGetModuleBaseName =(DWORD (WINAPI *)(HANDLE, HMODULE, LPTSTR, DWORD )) GetProcAddress( hInstLib, "GetModuleBaseNameW" ) ;
#else
        lpfGetModuleBaseName =(DWORD (WINAPI *)(HANDLE, HMODULE, LPTSTR, DWORD )) GetProcAddress( hInstLib, "GetModuleBaseNameA" ) ;
#endif

        if( lpfEnumProcesses == NULL || lpfEnumProcessModules == NULL || lpfGetModuleBaseName == NULL )
        {
            FreeLibrary(hInstLib);
            return 700;
        }
		 
		bResult = lpfEnumProcesses(aiPID, iCb, &iCbneeded);
		if(!bResult)
		{
			// Unable to get process list, EnumProcesses failed
            FreeLibrary(hInstLib);
			return 701;
		}

		// How many processes are there?
		iNumProc = iCbneeded/sizeof(DWORD);

		// Get and match the name of each process
		for(i = 0; i < iNumProc; i++)
		{
			// Get the (module) name for this process
			
			//strcpy_s(szName,"Unknown");
#if _UNICODE
            wcscpy_s(szName,_T("Unknown"));
#else
            strcpy_s(szName,_T("Unknown"));
#endif
			// First, get a handle to the process
	        hProc = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, aiPID[i]);
	        // Now, get the process name
	        if(hProc)
			{
               if( lpfEnumProcessModules( hProc, &hMod, sizeof(hMod), &iCbneeded) )
			   {
                  iLen = lpfGetModuleBaseName(hProc, hMod, szName, MAX_PATH);
			   }
			}
	        CloseHandle(hProc);
			// We will match regardless of lower or upper case
#ifdef BORLANDC
            if(strcmp(strupr(szName), szToTermUpper) == 0)
#else
            //if(strcmp(_strupr(szName),szToTermUpper)==0)
    #ifdef _UNICODE
            if(wcscmp(_wcsupr(szName),szToTermUpper)==0)
    #else
            if(strcmp(_strupr(szName),szToTermUpper)==0)
    #endif
#endif
			{
				// Process found, now terminate it
				iFound = 1;
				// First open for termination
				hProc = OpenProcess(PROCESS_TERMINATE, FALSE, aiPID[i]);
				if(hProc)
				{
					if(TerminateProcess(hProc,0))
					{
						// process terminated
						CloseHandle(hProc);
                        //FreeLibrary(hInstLib);      //循环查找进程  Pangtou  20160128
						//return 0;                   //循环查找进程  Pangtou  20160128
					}
					else
					{
						// Unable to terminate process
						CloseHandle(hProc);
                        FreeLibrary(hInstLib);
						return 602;
					}
				}
				else
				{
					// Unable to open process for termination
                    FreeLibrary(hInstLib);
					return 604;
				}
			}
		}
	}

	if(osvi.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS)
	{
		// Win/95 or 98 or ME
			
		hInstLib = LoadLibrary(_T("Kernel32.DLL"));
		if( hInstLib == NULL )
			return 702;

		// Get procedure addresses.
		// We are linking to these functions of Kernel32
		// explicitly, because otherwise a module using
		// this code would fail to load under Windows NT,
		// which does not have the Toolhelp32
		// functions in the Kernel 32.
		lpfCreateToolhelp32Snapshot = (HANDLE(WINAPI *)(DWORD,DWORD)) GetProcAddress( hInstLib, "CreateToolhelp32Snapshot" ) ;
		lpfProcess32First = (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32)) GetProcAddress( hInstLib, "Process32First" ) ;
		lpfProcess32Next = (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32)) GetProcAddress( hInstLib, "Process32Next" ) ;
		lpfModule32First = (BOOL(WINAPI *)(HANDLE,LPMODULEENTRY32)) GetProcAddress( hInstLib, "Module32First" ) ;
		lpfModule32Next = (BOOL(WINAPI *)(HANDLE,LPMODULEENTRY32)) GetProcAddress( hInstLib, "Module32Next" ) ;
		if( lpfProcess32Next == NULL ||
			lpfProcess32First == NULL ||
		    lpfModule32Next == NULL ||
			lpfModule32First == NULL ||
			lpfCreateToolhelp32Snapshot == NULL )
		{
			FreeLibrary(hInstLib);
			return 703;
		}
			
		// The Process32.. and Module32.. routines return names in all uppercase

		// Get a handle to a Toolhelp snapshot of all the systems processes.

		hSnapShot = lpfCreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) ;
		if( hSnapShot == INVALID_HANDLE_VALUE )
		{
			FreeLibrary(hInstLib);
			return 704;
		}
		
        // Get the first process' information.
        procentry.dwSize = sizeof(PROCESSENTRY32);
        bResult = lpfProcess32First(hSnapShot,&procentry);

        // While there are processes, keep looping and checking.
        while(bResult)
        {
		    // Get a handle to a Toolhelp snapshot of this process.
		    hSnapShotm = lpfCreateToolhelp32Snapshot( TH32CS_SNAPMODULE, procentry.th32ProcessID) ;
		    if( hSnapShotm == INVALID_HANDLE_VALUE )
			{
				CloseHandle(hSnapShot);
			    FreeLibrary(hInstLib);
			    return 704;
			}
			// Get the module list for this process
			modentry.dwSize = sizeof(MODULEENTRY32);
			bResultm = lpfModule32First(hSnapShotm,&modentry);

			// While there are modules, keep looping and checking
			while(bResultm)
			{
            //if(strcmp(modentry.szModule, szToTermUpper)==0)
#ifdef _UNICODE
            if(wcscmp(modentry.szModule, szToTermUpper)==0)
#else
            if(strcmp(modentry.szModule, szToTermUpper)==0)
#endif
				{
				    // Process found, now terminate it
				    iFound=1;
				    // First open for termination
				    hProc=OpenProcess(PROCESS_TERMINATE,FALSE,procentry.th32ProcessID);
				    if(hProc)
					{
					    if(TerminateProcess(hProc,0))
						{
						    // process terminated
							CloseHandle(hSnapShotm);
							CloseHandle(hSnapShot);
							CloseHandle(hProc);
                            //FreeLibrary(hInstLib);      //循环查找进程  Pangtou  20160128
                            //return 0;                   //循环查找进程  Pangtou  20160128
						}
					    else
						{
						    // Unable to terminate process
							CloseHandle(hSnapShotm);
							CloseHandle(hSnapShot);
							CloseHandle(hProc);
			                FreeLibrary(hInstLib);
						    return 602;
						}
					}
				    else
					{
					    // Unable to open process for termination
						CloseHandle(hSnapShotm);
						CloseHandle(hSnapShot);
			            FreeLibrary(hInstLib);
					    return 604;
					}
				}
				else
				{  // Look for next modules for this process
					modentry.dwSize=sizeof(MODULEENTRY32);
					bResultm=lpfModule32Next(hSnapShotm,&modentry);
				}
			}

			//Keep looking
			CloseHandle(hSnapShotm);
            procentry.dwSize = sizeof(PROCESSENTRY32);
            bResult = lpfProcess32Next(hSnapShot,&procentry);
        }
		CloseHandle(hSnapShot);
	}
	if(iFound == 0)
	{
		FreeLibrary(hInstLib);
		return 603;
	}
	FreeLibrary(hInstLib);
	return 0;
}
// 刷新任务栏图标
void RefurbishTray()
{
	RECT  WindowRect ;
	POINT  point ;
	int  x ;
	int  y ; 
	HWND  hwnd; 
	hwnd = ::FindWindow(_T("Shell_TrayWnd"), NULL ) ;
	hwnd = ::FindWindowEx(hwnd, 0, _T("TrayNotifyWnd"), NULL );

	::GetWindowRect(hwnd , &WindowRect ) ;
	::GetCursorPos(&point) ;

	for( x = 1 ; x < WindowRect.right - WindowRect.left - 1  ; x ++  )
	{
		for( y = 1 ; y < WindowRect.bottom - WindowRect.top - 1 ; y ++  )
		{
            //刷新任务栏图标 移动鼠标位置
			SetCursorPos( WindowRect.left + x, WindowRect.top + y ) ;
			Sleep(0);
		}
	}
	//还原鼠标位置
	SetCursorPos( point.x, point.y ) ;
	
}
// 关闭进程
extern "C" __declspec(dllexport) void KillProcess(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
    TCHAR parameter[MAX_PATH];
	ZeroMemory( parameter, MAX_PATH );
    int value;
    
    EXDLL_INIT();
	{
        popstring( parameter );
        
        value = KillProcessFromName( parameter );
        //wsprintf(parameter,"%d",value);
#ifdef UNICODE
        wsprintf(parameter, _T("%d"), value);
#else
        sprintf_s(parameter, "%d", value);
#endif
		pushstring( parameter );
		
		if(value == 0)
		{
		    //刷新任务栏图标
		    RefurbishTray();
		}
    }
}
// HostName
extern "C" void __declspec(dllexport) GetLocalHostName(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{  
	TCHAR cLocalHostName[MAX_PATH];
	ZeroMemory( cLocalHostName, MAX_PATH );

	EXDLL_INIT();
	{
		TCHAR* cHostName;
		cHostName = new TCHAR[255];
		ZeroMemory( cHostName, MAX_PATH );

		gethostname((char FAR*)cHostName,255);

        //strcpy_s( cLocalHostName, 255, cHostName );
#if _UNICODE
        wcscpy_s( cLocalHostName, 255, cHostName );
#else
        strcpy_s( cLocalHostName, 255, cHostName );
#endif

		pushstring( cLocalHostName );
	}
}
// System Language
extern "C" void __declspec(dllexport) GetSysLanguage(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	EXDLL_INIT();
	{
        LANGID lid = GetSystemDefaultLangID();
        CString LangID;
        LangID.Format(_T("%d"),lid);
        pushstring(LangID);
    }
}
// System Version
BOOL GetNtVersionNumbers(DWORD&dwMajorVer, DWORD& dwMinorVer,DWORD& dwBuildNumber)
{
    BOOL bRet= FALSE;
    HMODULE hModNtdll= NULL;
    if (hModNtdll= ::LoadLibraryW(L"ntdll.dll"))
    {
        typedef void (WINAPI *pfRTLGETNTVERSIONNUMBERS)(DWORD*,DWORD*, DWORD*);
        pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
        pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)::GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
        if (pfRtlGetNtVersionNumbers)
        {
           pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer,&dwBuildNumber);
           dwBuildNumber&= 0x0ffff;
           bRet = TRUE;
        }
 
        ::FreeLibrary(hModNtdll);
        hModNtdll = NULL;
    }
 
    return bRet;
}
extern "C" void __declspec(dllexport) GetSysVersion(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	TCHAR cSystemVersion[MAX_PATH];
	ZeroMemory( cSystemVersion, MAX_PATH );

	EXDLL_INIT();
    {
        DWORD a1,a2,a3;
        BOOL result;
        result = GetNtVersionNumbers(a1,a2,a3);
        CString strOSVersion;
        strOSVersion.Format(_T("%d.%d"),a1,a2);/*,a3*/
        
        //strcpy_s( cSystemVersion, strOSVersion );
#if _UNICODE
        wcscpy_s( cSystemVersion, strOSVersion );
#else
        strcpy_s( cSystemVersion, strOSVersion );
#endif

        
        pushstring( cSystemVersion );
        //OutputDebugString( cSystemVersion );
    }
}
// System Bit
BOOL IsWow64() 
{ 
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL); 
	LPFN_ISWOW64PROCESS fnIsWow64Process; 
	BOOL bIsWow64 = FALSE; 
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandle(_T("kernel32")),"IsWow64Process"); 
	if (NULL != fnIsWow64Process) 
	{ 
		fnIsWow64Process(GetCurrentProcess(),&bIsWow64);
	} 
	return bIsWow64; 
} 
extern "C" void __declspec(dllexport) GetSysBit(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	TCHAR cSystemBit[MAX_PATH];
	ZeroMemory( cSystemBit, MAX_PATH );

	EXDLL_INIT();
    {
        CString strOSBit;
        if (IsWow64())
        {
            strOSBit.Format(_T("%d"),64);
        }
        else
        {
            strOSBit.Format(_T("%d"),32);
        }
        
        //strcpy_s( cSystemBit, strOSBit );
#if _UNICODE
        wcscpy_s( cSystemBit, strOSBit );
#else
        strcpy_s( cSystemBit, strOSBit );
#endif
        
        pushstring( cSystemBit );
        //OutputDebugString( cSystemBit );
    }
}

// 提权
BOOL ProvidesRight()
{
	HANDLE hToken;
	BOOL fOK = FALSE;
	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
		{
			//printf("Can't lookup privilege value.\n");
			OutputDebugString(_T("Can't lookup privilege value.\n"));
		}
		tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
		if( !AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
		{
			//printf("Can't adjust privilege value.\n");
			OutputDebugString(_T("Can't adjust privilege value.\n"));
		}
		fOK = ( GetLastError() == ERROR_SUCCESS );
		CloseHandle(hToken);
	}
	return fOK;
}
extern "C" void __declspec(dllexport) GetProvidesRight(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	TCHAR cSystemProvidesRight[MAX_PATH];
	ZeroMemory( cSystemProvidesRight, MAX_PATH );

	EXDLL_INIT();
    {
        //提权申请
        if (ProvidesRight() == FALSE)
        {
	        int err = GetLastError();
	        CString csLastError;
	        csLastError.Format(_T("提权失败，不是系统管理员权限！ Error=%d"), err);
	        OutputDebugString(csLastError);
	        
            //strcpy_s( cSystemProvidesRight, _T("false") );
#if _UNICODE
            wcscpy_s( cSystemProvidesRight, _T("false") );
#else
            strcpy_s( cSystemProvidesRight, _T("false") );
#endif
        }
        else
        {
            //strcpy_s( cSystemProvidesRight, _T("true") );
#if _UNICODE
            wcscpy_s( cSystemProvidesRight, _T("true") );
#else
            strcpy_s( cSystemProvidesRight, _T("true") );
#endif
        }
        pushstring( cSystemProvidesRight );
    }
}
// File Exist
static bool  is_exist_file( TCHAR* file )
{
	//const std::string newfile(file);
#ifdef UNICODE
    const std::string newfile(wchar2string(file));
#else
    const std::string newfile(file);
#endif

#ifdef _WIN32
	if (_access(newfile.c_str(), 0) != -1)
#else
	if (access(newfile.c_str(), 0) != -1)
#endif
	{
		return true;
	}

	return false;
}
extern "C" void __declspec(dllexport) FileExist(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
    EXDLL_INIT();
    {
        TCHAR parameter[MAX_PATH];
	    ZeroMemory( parameter, MAX_PATH );
        popstring( parameter );
        
		int value = is_exist_file( parameter );
		//wsprintf( parameter, _T("%d"), value );
#ifdef UNICODE
        wsprintf(parameter, _T("%d"), value);
#else
        sprintf_s(parameter, _T("%d"), value);
#endif
		
		pushstring( parameter );
    }
}

//// Download Wait
//static UINT_PTR PluginCallback( enum NSPIM msg )
//{
//    //注册回调
//	//OutputDebugString("PluginCallback");
//	return 0;
//}
//extern "C" void __declspec(dllexport) StartDownload(HWND hwndParent, int string_size, char *variables, stack_t **stacktop, extra_parameters *extra )
//{
//    EXDLL_INIT();
//    extra->RegisterPluginCallback( g_hModule, PluginCallback );
//    {
//	    TCHAR dlUrl[MAX_PATH];
//	    TCHAR dlPath[MAX_PATH];
//
//	    ZeroMemory( dlUrl, MAX_PATH );
//	    ZeroMemory( dlPath, MAX_PATH );
//
//	    popstring( dlUrl );
//	    popstring( dlPath );
//	    int callbackID = popint();
//
//
//	    BOOL bRet = TRUE;
//	    BOOL bRes = FALSE;
//	    DWORD dwRead = 0;
//        DWORD dwWrite = 0;
//        TCHAR szBuff[MAX_PATH*10] = {0};
//        HINTERNET hSession = NULL;
//	    HINTERNET hInterUrl = NULL;
//        HANDLE hFile = INVALID_HANDLE_VALUE;
//
//        long lTempFileSize = 0;
//        long lPrecent = 0;
//        CString csPrecent;
//
//	    hSession = InternetOpen( _T("Mozilla/5.0 ( compatible; MSIE 9.0; Windows NT 6.1; Win32; x86; Trident/5.0 )"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0 );
//	    if (NULL == hSession)
//	    {
//		    bRet = FALSE;
//		    goto _Exit_Error;
//	    }
//
//	    hInterUrl = InternetOpenUrl(hSession, dlUrl, NULL, 0, INTERNET_FLAG_RELOAD, 0);
//	    if (NULL == hInterUrl)
//	    {
//		    bRet = FALSE;
//		    goto _Exit_Error;
//	    }
//
//	    //查询文件长度
//	    long lFileSize = 0;
//	    TCHAR wcBuf[1024] = _T("\0");
//        DWORD dwLen;
//	    dwLen = sizeof( wcBuf );
//	    DWORD bQuery;
//	    bQuery = HttpQueryInfo( hInterUrl, HTTP_QUERY_CONTENT_LENGTH, wcBuf, &dwLen, NULL );
//	    if ( !bQuery ) { return ; }
//	    lFileSize = atol( wcBuf )/100;
//    //#if _UNICODE
//    //	wstring wsLen( wcBuf, dwLen );
//    //	lFileSize = _wtol( wsLen.c_str() )/100;
//    //#else
//    //	string wsLen( wcBuf, dwLen );
//    //	lFileSize = atol( wsLen.c_str() )/100;
//    //#endif
//        
//        //创建文件
//	    hFile = CreateFile(dlPath, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
//	    if (INVALID_HANDLE_VALUE == hFile)
//	    {
//		    bRet = FALSE;
//		    goto _Exit_Error;
//	    }
//        
//	    while(1)
//	    {
//		    memset(szBuff, 0, sizeof(szBuff));
//		    bRes = InternetReadFile(hInterUrl, szBuff, sizeof(szBuff), &dwRead);
//		    if (!bRes)
//		    {
//			    bRet = FALSE;
//			    goto _Exit_Error;
//		    }
//		    if(0 == dwRead)
//		    {
//			    break;
//		    }
//
//		    bRes = WriteFile(hFile, szBuff, dwRead, &dwWrite, NULL);
//		    if (!bRes)
//		    {
//			    bRet = FALSE;
//			    goto _Exit_Error;
//		    }
//		    if (0 == dwWrite)
//		    {
//			    bRet = FALSE;
//			    goto _Exit_Error;
//		    }
//    		
//            lTempFileSize = lTempFileSize + dwRead;
//            lPrecent = lTempFileSize/lFileSize;
//            
//            //回调传值
//            csPrecent.Format(_T("%d%s"),lPrecent,_T("%"));
//            popstring(csPrecent.GetBuffer());
//            extra->ExecuteCodeSegment(callbackID -1, NULL);
//            
//		    if ( lFileSize == ( lTempFileSize/100 ) )
//		    {
//		        //csPrecent.Format(_T("100%"));
//		        //SetTrayIcon(0, csPrecent);
//			    break; 
//		    }
//	    }
//
//
//    _Exit_Error:
//	    if (INVALID_HANDLE_VALUE != hFile)
//	    {
//		    CloseHandle(hFile);
//	    }
//	    if (NULL != hInterUrl)
//	    {
//		    InternetCloseHandle(hInterUrl);
//	    }
//	    if (NULL != hSession)
//	    {
//		    InternetCloseHandle(hSession);
//	    }
//	    return ;
//    }
//}
