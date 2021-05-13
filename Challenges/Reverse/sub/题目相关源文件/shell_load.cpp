#include <stdio.h>
#include <windows.h>

//函数声明
BOOL Is32PEFile(LPVOID pFileBuffer);
VOID EncryptPEFile(LPVOID pFileBuffer,LPVOID pFileEncryBuffer ,DWORD size);


//加壳程序 
int main(int argc, int **argv)
{
	//1、获取Shell程序路径（只能给32位程序加壳）
	CHAR szShellName[] = "C:\\Users\\ZSKY\\Desktop\\shell\\Debug\\shell.exe"; //这个地方是壳子程序的路径★
	
	//2、获取Src的路径,命令行参数就是加壳的程序
	if (argc == 1)
	{
		printf("加壳失败!\n");
		printf("命令行参数为要加壳的程序!\n");
		return -1;
	}

	CHAR *szSrcName = (CHAR *)argv[1];

	
	//3、将Src读到内存当中并加密
	FILE * fpSrc = fopen(szSrcName, "rb");
	fseek(fpSrc, 0, SEEK_END);
	DWORD dwSrcFileSize = ftell(fpSrc);

	DWORD dwSrcAlignSize = (dwSrcFileSize % 0X1000) ? (dwSrcFileSize / 0X1000 + 1) * 0X1000: dwSrcFileSize;//获取原来文件对齐后的大小
	CHAR * pSrcBuffer = (CHAR *)malloc(dwSrcAlignSize);
	CHAR * pSrcEncryBuffer = (CHAR *)malloc(dwSrcAlignSize);
	memset(pSrcBuffer, 0, dwSrcAlignSize);
	fseek(fpSrc, 0, SEEK_SET);
	fread(pSrcBuffer, dwSrcAlignSize, 1, fpSrc);

	if (!Is32PEFile(pSrcBuffer))
	{
		printf("加壳失败\n");
		free(pSrcBuffer);
		fclose(fpSrc);
		return 0;
	}
	
	EncryptPEFile(pSrcBuffer, pSrcEncryBuffer, dwSrcAlignSize); //加密文件
	fclose(fpSrc);
	free(pSrcBuffer);

	//4、在Shell程序中新增一个节，将加密后的Src程序追加到Shell程序的新增节中 （程序为szSrcName_zsky.exe）
	char buffer[BUFSIZ] = { 0 };
	CHAR * szSrcShellName = buffer;
	memcpy(szSrcShellName, szSrcName, strlen(szSrcName) - 4);
	strcat(szSrcShellName, "_zsky.exe");
	


	FILE * fpShell = fopen(szShellName, "rb");			//Shell程序
	FILE * fpShellSrc = fopen(szSrcShellName, "wb");	//加壳后的程序存放位置 与 源程序目录一样 加后缀_zsky
	
	//将Shell程序读到内存当中
	fseek(fpShell, 0, SEEK_END);
	DWORD dwShellFileSize = ftell(fpShell);
	CHAR * pShellBuffer = (CHAR *)malloc(dwShellFileSize);
	fseek(fpShell, 0, SEEK_SET);
	fread(pShellBuffer, dwShellFileSize, 1, fpShell);

	IMAGE_DOS_HEADER * pidh = (IMAGE_DOS_HEADER * )pShellBuffer;
	IMAGE_NT_HEADERS * pinh = (IMAGE_NT_HEADERS *)((DWORD)pShellBuffer + pidh->e_lfanew);
	IMAGE_FILE_HEADER * ppeh = (IMAGE_FILE_HEADER *)((DWORD)pinh + 4);
	IMAGE_OPTIONAL_HEADER32 * pOptionHeader = (IMAGE_OPTIONAL_HEADER32 *)((DWORD)ppeh + sizeof(IMAGE_FILE_HEADER));
	IMAGE_SECTION_HEADER * pSec = (IMAGE_SECTION_HEADER *)((DWORD)pOptionHeader + ppeh->SizeOfOptionalHeader);

	pinh->FileHeader.NumberOfSections += 1;					//将节表的数量加1

	//修改可选头的SizeOfImage
	pinh->OptionalHeader.SizeOfImage += dwSrcAlignSize;		//将SizeOfImage 增大
	
	//修改节表属性
	int newSecIndex = pinh->FileHeader.NumberOfSections - 1;
	memcpy((void *)&pSec[newSecIndex], (void *)&pSec[0], sizeof(pSec[0]));
	pSec[newSecIndex].Misc.VirtualSize = dwSrcAlignSize;
	memcpy(pSec[newSecIndex].Name, ".zsky", 8);
	pSec[newSecIndex].SizeOfRawData = dwSrcAlignSize;
	
	//上一节在内存对齐后的大小
	DWORD dwLastVirtualSize = pSec[newSecIndex - 1].Misc.VirtualSize;
	DWORD dwVirtualAlignSize = (dwLastVirtualSize % 0X1000) ? (dwLastVirtualSize / 0X1000 + 1) * 0X1000 : dwLastVirtualSize;//获取原来文件对齐后的大小
	pSec[newSecIndex].VirtualAddress = pSec[newSecIndex - 1].VirtualAddress + dwVirtualAlignSize;
	pSec[newSecIndex].PointerToRawData = pSec[newSecIndex - 1].PointerToRawData + pSec[newSecIndex - 1].SizeOfRawData;
	
	fseek(fpShellSrc, 0, SEEK_SET);
	fwrite(pShellBuffer, 1, dwShellFileSize, fpShellSrc);
	//往文件末尾添加加密后的PE文件
	fwrite(pSrcEncryBuffer, 1, dwSrcAlignSize, fpShellSrc);
	printf("加壳成功!\n");
	printf("加壳后的程序: %s\n", szSrcShellName);
	
	//释放资源
	free(pSrcEncryBuffer);
	free(pShellBuffer);
	fclose(fpShellSrc);
	fclose(fpShell);
	return 0;
}

//检测是不是32位PE文件
BOOL Is32PEFile(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (*(PWORD)pDosHeader != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return FALSE;
	}
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return FALSE;
	}
	if (pNTHeader->OptionalHeader.Magic == 0X20B)
	{
		printf("您打开的64位EXE程序，本加壳软件只能给32位EXE程序加壳!\n");
		return FALSE;
	}

	return TRUE;
}

//加密PE文件
VOID EncryptPEFile(LPVOID pFileBuffer,LPVOID pFileEncryBuffer, DWORD size)
{
	CHAR * pPeBuffer = (CHAR *)pFileBuffer;
	CHAR * pPeEncryBuffer = (CHAR *)pFileEncryBuffer;
	//简单的异或加密
	for (int i = 0; i < size; i++)
	{
		pPeEncryBuffer[i] = pPeBuffer[i] ^ 100;
	}
}