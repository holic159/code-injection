#include <Windows.h>
#include <stdio.h>

BOOL InjectCode(DWORD dwPID);
DWORD WINAPI ThreadProc(LPVOID lParam);


// CreateFile
typedef HANDLE(WINAPI *PFCREATEFILE)
(
	LPCTSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	);

// WriteFile
typedef BOOL(WINAPI *PFWRITEFILE)
(
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	);

// CloseHandle
typedef BOOL(WINAPI *PFCLOSEHANDLE)
(
	HANDLE hObject
	);

// Thread Parameter
typedef struct _THREAD_PARAM
{
	FARPROC pFunc[6];
	char szBuf[4][128];
	wchar_t filename[100];
	wchar_t content[100];
} THREAD_PARAM, *PTHREAD_PARAM;

// LoadLibraryA()
typedef HMODULE(WINAPI *PFLOADLIBRARYA)
(
	LPCSTR lpLibFileName
	);

//GetProcAddress()
typedef FARPROC(WINAPI *PFGETPROCADDRESS)
(
	HMODULE hModule,
	LPCSTR lpProcName
	);

// MessageBoxA()
typedef int (WINAPI *PFMESSAGEBOXA)
(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT uType
	);

// Thread Procedure
DWORD WINAPI ThreadProc(LPVOID lParam)
{
	PTHREAD_PARAM pParam = (PTHREAD_PARAM)lParam;
	HMODULE hMod = NULL;
	FARPROC pFunc = NULL;
	HANDLE hFile;
	DWORD temp;
	// LoadLibraryA("user32.dll")
	// pParam -> pFunc[0] -> kernel32!LoadLibraryA()
	// pParam - > szBuf[0] -> "user32.dll"
	hMod = ((PFLOADLIBRARYA)pParam->pFunc[0])(pParam->szBuf[0]);

	// GetProcAddress("MessageBoxA")
	// pParam -> pFunc[1] -> kernel32!GetProcAddress()
	// pParam -> szBuf[1] -> "MessageBoxA"
	pFunc = (FARPROC)((PFGETPROCADDRESS)pParam->pFunc[1])(hMod, pParam->szBuf[1]);

	// MessageBoxA(NULL, "Code Injection Test", "Code Injection Test - Zairo", MB_OK)
	// pParam->szBuf[2] -> "Code Injection Test"
	// pParam->szBuf[3] -> "Code Injection Test - Zairo"
	((PFMESSAGEBOXA)pFunc)(NULL, pParam->szBuf[2], pParam->szBuf[3], MB_OK);

	// hFile = CreateFile("zairo.txt",(GENERIC_READ | GENERIC_WRITE), 0, NULL, CREATE_ALWAYS, 0, NULL);
	// pParam->filename[0] -> "zairo.txt"

	hFile = ((PFCREATEFILE)pParam->pFunc[2])(pParam->filename,(GENERIC_READ | GENERIC_WRITE), 0, NULL, CREATE_ALWAYS, 0, NULL);

	// WriteFile(hFile, pParam->content, sizeof(TCHAR) * 13, (LPDWORD)temp, NULL);
	
	((PFWRITEFILE)pParam->pFunc[3]) (hFile, pParam->content, sizeof(TCHAR) * 12, &temp, NULL);

	// CloseHandle(hFile)

	((PFCLOSEHANDLE)pParam->pFunc[4])(hFile);

	return 0;
}
BOOL InjectCode(DWORD dwPID)
{
	HMODULE hMod = NULL;
	THREAD_PARAM param = { 0, };
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID pRemoteBuf[2] = { 0, };
	DWORD dwSize = 0;

	hMod = GetModuleHandleA("kernel32.dll");

	// set THREAD_PARAM
	param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
	param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");
	param.pFunc[2] = GetProcAddress(hMod, "CreateFileW");
	param.pFunc[3] = GetProcAddress(hMod, "WriteFile"); 
	param.pFunc[4] = GetProcAddress(hMod, "CloseHandle"); 

	strcpy_s(param.szBuf[0], "user32.dll");
	strcpy_s(param.szBuf[1], "MessageBoxA");
	strcpy_s(param.szBuf[2], "Code Injection Test");
	strcpy_s(param.szBuf[3], "Code Injection Test - Zairo");

	
	param.filename[0] = 'C';
	param.filename[1] = ':';
	param.filename[2] = '\\';
	param.filename[3] = 't';
	param.filename[4] = 'e';
	param.filename[5] = 'm';
	param.filename[6] = 'p';
	param.filename[7] = '\\';
	param.filename[8] = 'z';
	param.filename[9] = 'a';
	param.filename[10] = 'i';
	param.filename[11] = 'r';
	param.filename[12] = 'o';
	param.filename[13] = '.';
	param.filename[14] = 't';
	param.filename[15] = 'x';
	param.filename[16] = 't';
	param.filename[17] = '\0';
	param.content[0] = 'h';
	param.content[1] = 'e';
	param.content[2] = 'l';
	param.content[3] = 'l';
	param.content[4] = 'o';
	param.content[5] = ' ';
	param.content[6] = 'w';
	param.content[7] = 'o';
	param.content[8] = 'r';
	param.content[9] = 'l';
	param.content[10] = 'd';
	param.content[11] = '!';
	param.content[12] = '\0';

	// Open Process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, // dwDesiredAccess
		FALSE, // bInheritHandle
		dwPID); // dwProcessId

				// Allocation for THREAD_PARAM
	dwSize = sizeof(THREAD_PARAM);
	pRemoteBuf[0] = VirtualAllocEx(hProcess, // hProcess
		NULL,  // lpAddress
		dwSize, // dwSize
		MEM_COMMIT, // flAllocationType
		PAGE_READWRITE); // flProtect
	WriteProcessMemory(hProcess, // hProcess
		pRemoteBuf[0], // lpBaseAddress
		(LPVOID)&param, // lpBuffer
		dwSize, // nSize
		NULL); // [out]
			   // lpNumberOfBytesWritten

			   // Allocation for ThreadProc()
	dwSize = (DWORD)InjectCode - (DWORD)ThreadProc;
	pRemoteBuf[1] = VirtualAllocEx(hProcess, // hProcess
		NULL, // lpAddress
		dwSize, // dwSize
		MEM_COMMIT, // flAllocationType
		PAGE_EXECUTE_READWRITE); // flProtect

	WriteProcessMemory(hProcess,	// hProcess
		pRemoteBuf[1],	// lpBaseAddress
		(LPVOID)ThreadProc,	// lpBuffer
		dwSize,	// nSize
		NULL); // [out]
			   // lpNumberOfBytesWritten

	hThread = CreateRemoteThread(hProcess, // hProcess
		NULL,	// lpThreadAttributes
		0,	// dwStackSize
		(LPTHREAD_START_ROUTINE)pRemoteBuf[1],
		pRemoteBuf[0], // lpParameter
		0,	// dwCreationFlags
		NULL);	// lpThreadId

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}
int main(int argc, char *argv[])
{
	DWORD dwPID = 0;
	PROCESS_INFORMATION pi = { 0, };
	STARTUPINFO si = { 0, };
	wchar_t path[] = L"calc.exe";
	HANDLE hHandle;

	// calc.exe 프로세스 오픈
	if (!(CreateProcess(NULL, path, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))) {
		printf("Can't open calc process.\n");
		exit(0);
	}

	Sleep(100);

	//code injection
	dwPID = (DWORD)pi.dwProcessId;
	InjectCode(dwPID);
}


