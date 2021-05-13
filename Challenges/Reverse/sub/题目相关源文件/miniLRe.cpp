#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#pragma comment(linker,"/INCLUDE:__tls_used")

//假的flag 为 miniLctf{Th1s_1s_th4_fak4_f1ag!}
//真的flag 为 miniLctf{Re_1s_s0_1nt4r4st1ng!!}


//定义函数指针
typedef NTSTATUS(__stdcall* pNtQueryInformationProcess)(
	IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
	);

char correct_enc[32] = { 90, 38, 89, 38, 123, 92, 67, 81, 84, 109, 82, 104, 14, 76, 104, 76, 15, 104, 14, 89, 67, 3, 77, 3, 76, 67, 14, 89, 80, 30, 30, 74 };
bool correct_check(char* flag, int len)
{
	if (len != 32)
		return false;
	
	for (int i = 0; i < len; i++)
	{
		char tmp = ((flag[i] ^ 0X55) + 4) ^ 0X66;
		if (tmp != correct_enc[i])
			return false;
	}
	return true;
}

char fake_enc[32] = { 90, 70, 89, 70, 123, 92, 67, 81, 116, 99, 71, 14, 76, 104, 14, 76, 104, 67, 71, 3, 104, 81, 94, 68, 3, 104, 81, 14, 94, 80, 30, 74 };
bool fake_check(char* flag, int len)
{
	if (len != 32)
		return false;

	for (int i = 0; i < len; i++)
	{
		char tmp = ((flag[i] ^ 0X66) + 4) ^ 0X55;
		if (tmp != fake_enc[i])
			return false;
	}
	return true;
}

//定义一个函数指针,指明检查flag的函数
bool (*check)(char* flag, int len) = fake_check;

//TLS回调函数 ---反调试模块
void NTAPI TLS_CALLBACK1(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	DWORD dwDebugPort;				//调试端口
	HMODULE hModule = LoadLibrary(TEXT("Ntdll.dll"));
	pNtQueryInformationProcess ntQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	ntQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwDebugPort, sizeof(dwDebugPort), NULL);
	if (dwDebugPort) //如果正在被调试，则KEY是错误的并且加密算法是错误的
	{
		check = fake_check;
	}
	else {			//如果正在被调试，则KEY是正确的并且加密算法是正确的
		check = correct_check;
	}
}

int main()
{
	char flag[50] = { 0 };
	printf("Please input your flag: ");
	scanf("%s", flag);
	
	if (check(flag, strlen(flag)))
	{
		printf("Congratulation~~~");
	}
	else {
		printf("Try again~~~");
	}

	getchar();
	getchar();
	return 0;
}


#pragma data_seg(".CRT$XLX")				
PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { TLS_CALLBACK1,  NULL };
#pragma data_seg()