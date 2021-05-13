// flag为 miniLctf{y0u_a1r4ady_und4rstand_th4_w1nd0ws_exc4pt1On_handl1e_m4chan1sm}
#include <stdio.h>
#include <windows.h>
#include <string.h>
#pragma comment(linker,"/INCLUDE:__tls_used")


long NTAPI VectExcepHandler(PEXCEPTION_POINTERS pExcepInfo)
{
	if (pExcepInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		//验证flag的偶数位
		char* _flag = (char*)(pExcepInfo->ContextRecord->Ebx + 9);
		char _enc1[] = { 16, 4, 24, 11, 24, 16, 4, 21, 11, 5, 31, 46, 33, 46, 72, 21, 6, 46, 17, 69, 5, 62, 46, 24, 21, 72, 46, 69, 33, 31, 10 };
		for (int i = 0; i < sizeof(_enc1); i++)
		{
			if (_enc1[i] != (((_flag[i * 2] ^ 55) + 4) ^ 66))
			{
				pExcepInfo->ContextRecord->Eip += 0X42;		//失败的地方
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		pExcepInfo->ContextRecord->Eip += 7;				//如果偶数位验证成功，则触发另一个异常(int 3)，进入SEH函数开始验证奇数位
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

int seh_filter(unsigned int code, struct _EXCEPTION_POINTERS* pExcepInfo)
{
	if (pExcepInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
	{
		//验证flag的奇数位
		char* _flag = (char*)(pExcepInfo->ContextRecord->Ebx + 9);
		char _enc2[] = {33, 86, 32, 45, 125, 86, 71, 45, 98, 112, 125, 109, 45, 110, 71, 33, 98, 124, 114, 97, 32, 71, 121, 71, 69, 124, 68, 114, 112, 32, 68};
		for (int i = 0; i < sizeof(_enc2); i++)
		{
			if (_enc2[i] != (((_flag[i * 2+1] ^ 77) - 4) ^ 0X13 ^ (pExcepInfo->ContextRecord->Eip & 0XFF)))
			{
				pExcepInfo->ContextRecord->Eip += 0X36;		//失败的地方
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		pExcepInfo->ContextRecord->Eip += 0X3F;				//跳转到成功
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void NTAPI TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	AddVectoredExceptionHandler(1, &VectExcepHandler);
}



bool CheckFlagFormat(char* flag)
{
	char prefix[10] = { 109,105,110,105,76,99,116,102,123, 0 };

	if (strlen(flag) > 72 || strlen(flag) < 10 || strncmp(flag, prefix, 9) || flag[71] != '}')
		return false;

	return true;
}

void PrintSuccess()
{
	char success[30] = { 67, 111, 110, 103, 114, 97, 116, 117, 108, 97, 116, 105, 111, 110, 33, 0 }; 
	printf("%s", success);
}

void PrintFailed()
{
	char failed[30] = { 84,114,121,32,97,103,97,105,110,33 ,0 };
	printf("%s", failed);
}


int main()
{
	char flag[100] = { 0 };
	char inputHint[100] = { 80,108,101,97,115,101,32,105,110,112,117,116,32,121,111,117,114,32,102,108,97,103,58,32,0 }; //Please input your flag:
	printf("%s", inputHint);
	scanf("%s", flag);
	if (!CheckFlagFormat(flag))
		goto LabelFailed;

	__try
	{
		__asm {
			lea ebx, flag;
			xor eax, eax;
			mov dword ptr ds : [eax] , 0;
			mov edx, 0;
			div edx;
		}
	}
	__except (seh_filter(GetExceptionCode(), GetExceptionInformation()))
	{
		
	}
LabelFailed:
	PrintFailed();
	return 0;
	PrintSuccess();
	return 0;
}

#pragma data_seg(".CRT$XLX")				
PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { TLS_CALLBACK,  NULL };
#pragma data_seg()