#include <stdio.h>
#include <windows.h>

typedef DWORD(WINAPI *_TZwUnmapViewOfSection)(HANDLE, PVOID);
BOOL PeLoad(HANDLE hProcess, BYTE * peFile, BYTE * peRam, int size);
DWORD FileBufferToImageBuffer(LPVOID pFileBuffer, LPVOID pImageBuffer);
VOID DecryptPEFile(LPVOID peEncryFile, DWORD dwSize);

//壳子程序
int main()
{
	TCHAR szShellName[BUFSIZ] = {0};
	GetModuleFileName(NULL, szShellName, BUFSIZ);  //获取壳子程序的路径
	//printf("当前模块路径为: %s\n", szShellName);
	
	//1、读取主模块的数据
	FILE * fpShellFile = fopen(szShellName, "rb");
	fseek(fpShellFile, 0, SEEK_END);
	DWORD dwShellFileSize = ftell(fpShellFile);
	CHAR * pShellFile = (CHAR *)malloc(dwShellFileSize);
	fseek(fpShellFile, 0, SEEK_SET);
	fread(pShellFile, 1, dwShellFileSize, fpShellFile);


	IMAGE_DOS_HEADER * pidh = (IMAGE_DOS_HEADER *)pShellFile;
	IMAGE_NT_HEADERS * pinh = (IMAGE_NT_HEADERS *)((DWORD)pShellFile + pidh->e_lfanew);
	IMAGE_FILE_HEADER * ppeh = (IMAGE_FILE_HEADER *)((DWORD)pinh + 4);
	IMAGE_OPTIONAL_HEADER32 * pOptionHeader = (IMAGE_OPTIONAL_HEADER32 *)((DWORD)ppeh + sizeof(IMAGE_FILE_HEADER));
	IMAGE_SECTION_HEADER * pSec = (IMAGE_SECTION_HEADER *)((DWORD)pOptionHeader + ppeh->SizeOfOptionalHeader);


	
	//2、解密得到原来的PE文件
	//申请内存用来存储解密后的PE文件
	DWORD dwPESize = pSec[pinh->FileHeader.NumberOfSections - 1].SizeOfRawData;
	DWORD dwPEPoint = pSec[pinh->FileHeader.NumberOfSections - 1].PointerToRawData;
	BYTE * PEFILE = (BYTE *)malloc(dwPESize);
	fseek(fpShellFile, dwPEPoint, SEEK_SET);
	fread(PEFILE, 1, dwPESize, fpShellFile);
	DecryptPEFile(PEFILE, dwPESize);


	//3、以挂起的形式创建进程
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	si.cb = sizeof(si);
	BOOL res = CreateProcess(
		szShellName,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED ,
		NULL,
		NULL,
		&si,
		&pi
	);

	//4、获取外壳的CONTEXT结构
	CONTEXT contx;
	contx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &contx);
	//printf("子进程PID: %d\n", pi.dwProcessId);
	//printf("%#X\n", contx.Eax); //OEP + ImageBase
	BYTE * baseAddress = (BYTE *)(contx.Ebx + 8);
	DWORD dwImageBase = 0;
	ReadProcessMemory(pi.hProcess, baseAddress, &dwImageBase, 4, NULL);
	//printf("ImageBase: %#X\n", *(DWORD *)szBuffer);  //ImageBase
	
	//5、卸载外壳程序的文件镜像
	// 获取 ZwUnmapViewOfSection 函数指针 ZwUnmapViewOfSection
	HMODULE hModuleNt = LoadLibrary("ntdll.dll");
	if (hModuleNt == NULL)
	{
		//printf("获取ntdll句柄失败\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	
	_TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
	if (pZwUnmapViewOfSection == NULL)
	{
		//printf("获取 ZwUnmapViewOfSection 函数指针失败\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	pZwUnmapViewOfSection(pi.hProcess, (PVOID)dwImageBase);



	//6、在指定的位置分配空间：位置就是src的ImageBase，大小是SizeOfImage(VirtualAllocEx)
	IMAGE_DOS_HEADER * pidhsrc = (IMAGE_DOS_HEADER *)PEFILE;
	IMAGE_NT_HEADERS * pinhsrc = (IMAGE_NT_HEADERS *)(pidhsrc->e_lfanew + PEFILE);
	LPVOID pImageBase = VirtualAllocEx(pi.hProcess, (LPVOID)pinhsrc->OptionalHeader.ImageBase, pinhsrc->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if ((DWORD)pImageBase != pinhsrc->OptionalHeader.ImageBase)
	{
		//printf("VirtualAllocEx 错误码: 0x%X\n", GetLastError()); // 0x1e7 试图访问无效地址
		//printf("申请到的指针: 0x%X, 期望的地址: 0x%X\n", (DWORD)pImageBase, pinhsrc->OptionalHeader.ImageBase);
		TerminateThread(pi.hThread, 0);
		return -1;
	}

	
	//7、拉伸PE文件，放到此位置
	PeLoad(pi.hProcess, PEFILE, (BYTE *)pImageBase, pinhsrc->OptionalHeader.SizeOfImage);
	
	//8、修改外壳程序的Context
	contx.Eax = pinhsrc->OptionalHeader.AddressOfEntryPoint + pinhsrc->OptionalHeader.ImageBase;
	DWORD imageBase = pinhsrc->OptionalHeader.ImageBase;
	WriteProcessMemory(pi.hProcess, LPVOID(contx.Ebx + 8), &imageBase, 4, NULL);
	SetThreadContext(pi.hThread, &contx);
	ResumeThread(pi.hThread);
	//释放资源区
	free(pShellFile);
	free(PEFILE);
	return 0;
}



// 将PE文件拉伸
//pFileBuffer：源文件读到内存去的首地址
//pImageBuffer： 拉伸后文件读到内存去的首地址
// 返回拉伸后的文件在内存中对齐后的大小
DWORD FileBufferToImageBuffer(LPVOID pFileBuffer, LPVOID pImageBuffer)
{
	IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER *)pFileBuffer;
	IMAGE_NT_HEADERS * pNtHeader = (IMAGE_NT_HEADERS *)(pDosHeader->e_lfanew + (DWORD)pDosHeader);
	IMAGE_FILE_HEADER * pPEHeader = (IMAGE_FILE_HEADER *)((DWORD)pNtHeader + 4);
	IMAGE_OPTIONAL_HEADER32 * pOptionHeader = (IMAGE_OPTIONAL_HEADER32 *)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	IMAGE_SECTION_HEADER * pSectionHeader = (IMAGE_SECTION_HEADER *)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	memset(pImageBuffer, 0, pNtHeader->OptionalHeader.SizeOfImage);
	//复制DOS头 + PE头 + 节表 + 文件对齐
	memcpy(pImageBuffer, pFileBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);
	for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)pImageBuffer + pSectionHeader[i].VirtualAddress), (LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData);
	}

	return pNtHeader->OptionalHeader.SizeOfImage;
}


//解密PE文件
VOID DecryptPEFile(LPVOID peEncryFile, DWORD dwSize)
{
	CHAR * _peEncryFile = (CHAR *)peEncryFile;
	for (int i = 0; i < dwSize; i++)
	{
		_peEncryFile[i] ^= 100;
	}
}


//模拟PE加载
//hProcess:进程句柄
//peFile:PE拉伸前的地址（在本进程中）
//peRam：ImageBase（在hProcess进程中）
//size:PE拉伸后对齐的大小
BOOL PeLoad(HANDLE hProcess, BYTE * peFile, BYTE * peRam, int size)
{
	BYTE * peImage = (BYTE *)malloc(size);
	FileBufferToImageBuffer(peFile, peImage);
	BOOL isSuccess = WriteProcessMemory(hProcess, peRam, peImage, size, NULL);
	free(peImage);
	return isSuccess;
}