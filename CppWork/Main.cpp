//2015 - Oguz Kartal

#include <Windows.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


typedef HANDLE (WINAPI *CreateFileWPtr)(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	);

typedef BOOL (WINAPI *WriteFilePtr)(
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
);



typedef struct _relocBranchInfo
{
	unsigned char *addr;
	int relOffset;
	int size;
}relocBranchInfo;

typedef struct _relocBranchList
{
	struct _relocBranchList *head;
	struct _relocBranchList *next;
	relocBranchInfo *rbi;
}relocBranchList;


typedef struct _HOOKINFO
{
	relocBranchList *relocList;
	void *originalApi;
	void *hookFunction;
}HOOKINFO;


#define allocMem(size, type) ((type *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size))

#define allocStructMem(type) allocMem(sizeof(type),type)

#define freeMem(ptr) HeapFree(GetProcessHeap(),0,ptr)


int xprintf(const char *fmt, ...) 
{
	char pbuf[256] = { 0 };

	HANDLE console;
	va_list argList;
	int len;

	va_start(argList, fmt);

	len = vsprintf(pbuf, fmt, argList);

	console = GetStdHandle(STD_OUTPUT_HANDLE);

	WriteConsoleA(console, pbuf, len, NULL, NULL);

	va_end(argList);

	return len;
}

int isMov(unsigned char opCode) {
	if (opCode >= 0x88 && opCode <= 0x8D)
		return 1;

	if (opCode >= 0xA0 && opCode <= 0xA3)
		return 1;

	switch (opCode)
	{
		case 0xB0:
		case 0xB8:
		case 0xC6:
		case 0xC7:
			return 1;
	}

	return 0;
}


void recalculateAndPatch(unsigned char *origFuncBody, unsigned char *newFuncBody, relocBranchInfo *rbi)
{
	BOOL isNewUpper = newFuncBody > origFuncBody;

	int shiftSize;
	int newOffset;

	shiftSize = isNewUpper ? newFuncBody - origFuncBody : origFuncBody - newFuncBody;

	newOffset = rbi->relOffset + shiftSize;

	xprintf("Patch: %x -> %x\n",rbi->relOffset, newOffset);

	int oldInstOffset= rbi->addr - origFuncBody;

	*((int *)(newFuncBody + oldInstOffset)) = newOffset;
}



CreateFileWPtr originalCreateFile = NULL;
WriteFilePtr originalWriteFile = NULL;

HOOKINFO *writeFileHook = NULL;

HANDLE WINAPI hooked_CreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	HANDLE handle;

	
	wprintf(L"Hooked CreateFileW: Filename: %s, Redirected to: D:\\HOOKED_FILE.txt", lpFileName);

	lpFileName = L"D:\\HOOKED_FILE.txt";

	handle = originalCreateFile(
		lpFileName, 
		dwDesiredAccess, 
		dwShareMode, 
		lpSecurityAttributes, 
		dwCreationDisposition, 
		dwFlagsAndAttributes, 
		hTemplateFile);

	
	return handle;
}

BOOL WINAPI hooked_WriteFile(
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	)
{
	BOOL result;
	const char *hookMsg = "HOOKING HARIC, ";
	char *manipData = allocMem(nNumberOfBytesToWrite + 64, char);
	int hookMsgLen = strlen(hookMsg);

	xprintf("WriteFile cagrisi yakalandi! Gelen veri: (%s)\n", lpBuffer);

	strcpy(manipData, hookMsg);
	strcat(manipData, (const char *)lpBuffer);

	
	result = originalWriteFile(hFile, manipData, nNumberOfBytesToWrite + hookMsgLen, lpNumberOfBytesWritten, lpOverlapped);


	if (result)
	{
		//kendi datamizi yazilan data uzunlugundan cikaralim
		*lpNumberOfBytesWritten -= hookMsgLen;

		xprintf("%d byte yazildi", *lpNumberOfBytesWritten);
	}
	else
		xprintf("WriteFile basarisiz.");

	freeMem(manipData);

	return result;
}



#define OC_RET				0xc3
#define OC_RET_N			0xc2
#define OC_CALL_REL			0xe8
#define OC_CALL_MODRM		0xff
#define OC_JCC_NEAR			0x0f

#define OC_JCC_BEGIN		0x80
#define OC_JCC_END			0x8F

#define OCX_CALL			2
#define OCX_CALLF			3
#define OCX_JMP				4
#define OCX_JMPF			5


/*
0 -> INC		R / M8 / M16 / M32
1 -> DEC		R / M8 / M16 / M32
2 -> CALL		R / m16 / m32
3 -> CALLF		M16 : 16 / 32
4 -> JMP		R / m16 / 32
5 -> JMPF		M16 : 16 / 32
6 -> PUSH		R / M16 / 32
*/

#define getInstrByModrm(modRm) ((modRm >> 3)  & 7)

BOOL is64bit = FALSE;
BOOL hookInit = FALSE;

BOOL is64BitProcess()
{
	HANDLE procImageFile;
	IMAGE_DOS_HEADER dosHdr;
	IMAGE_NT_HEADERS ntHdr;
	DWORD read;
	HMODULE mod;
	wchar_t fname[MAX_PATH] = { 0 };

	mod = GetModuleHandle(NULL);

	GetModuleFileNameW(mod, fname, MAX_PATH);

	procImageFile = CreateFile((LPCWSTR)fname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (procImageFile == INVALID_HANDLE_VALUE)
		return FALSE;

	ReadFile(procImageFile, &dosHdr, sizeof(IMAGE_DOS_HEADER), &read, NULL);

	SetFilePointer(procImageFile, dosHdr.e_lfanew, NULL, FILE_BEGIN);

	ReadFile(procImageFile, &ntHdr, sizeof(IMAGE_NT_HEADERS), &read, NULL);

	CloseHandle(procImageFile);

	is64bit = ntHdr.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;

	return is64bit;
}


void addReloc(HOOKINFO *hook, unsigned char *addr, int offset, int size)
{
	relocBranchInfo *rbi = allocStructMem(relocBranchInfo);
	relocBranchList *node = allocStructMem(relocBranchList);


	rbi->addr = addr;
	rbi->relOffset = offset;
	rbi->size = size;

	if (hook->relocList == NULL)
	{
		hook->relocList = node;
		node->head = node;
		node->next = NULL;
		node->rbi = rbi;
	}
	else
	{
		hook->relocList->next = node;
		node->head = hook->relocList->head;
		node->next = NULL;
		node->rbi = rbi;

		hook->relocList = node;
	}
}

int verbose = 1;


HOOKINFO *hookAPIFunction(const char *lib, const char *func, unsigned char *hookFunction)
{
	HOOKINFO *hook = NULL;
	int routineCodeSize = 0;
	unsigned char *originalProc = NULL;
	unsigned char *codeBytePtr = NULL;
	HMODULE hlib = NULL;
	DWORD oldProtection = 0;
	int maxCodeLength = 1024;

	unsigned char opCode;
	
	void *newFunc = NULL;

	void *requiredFunctionAddress = NULL;

	if (!hookInit)
		is64BitProcess();

	hlib = LoadLibraryA(lib);

	originalProc = (unsigned char *)GetProcAddress(hlib, func);

	codeBytePtr = originalProc;

	int off;

	hook = allocStructMem(HOOKINFO);

	if (!hook)
		return NULL;

	while (routineCodeSize == 0)
	{
		if (maxCodeLength-- <= 0)
			return NULL;

		switch (*codeBytePtr)
		{
			case OC_RET:
			{
				opCode = *(codeBytePtr + 1);

				//bak bakalim gercekten rutin sonunda miyiz?
				if (opCode == 0x90 || opCode == 0xcc || opCode == 0x00)
				{
					routineCodeSize = ((codeBytePtr + 1) - originalProc);

					if (verbose)
						xprintf("+ RET\n\n");
				}
			}
			break;
			case OC_RET_N:
			{
				opCode = *(codeBytePtr + 2);

				if (opCode == 0x90 || opCode == 0xcc || opCode == 0x00)
				{
					routineCodeSize = ((codeBytePtr + 3) - originalProc); //ret + 2 byte rel16 byte ret val
					
					if (verbose)
						xprintf("+ RET X\n\n");
				}
			}
			break;
			case OC_CALL_REL:
			{
				if (isMov(*(codeBytePtr - 1)))
					break;

				off = *((int *)(codeBytePtr + 1));
				addReloc(hook,codeBytePtr + 1, off,4);

				if (verbose)
					xprintf("CALL_R8 found at 0x%p -> RELOFFSET: %x (%d)\n\n", codeBytePtr, off,off);

				codeBytePtr += 4;

			}
			break;
			case OC_CALL_MODRM:
			{
				//check previous opcode is one of the MOV opcode.
				//0xFF is EDI,EDI operand for MOV
				if (isMov(*(codeBytePtr - 1)))
					break;

				if (getInstrByModrm(*(codeBytePtr + 1)) == OCX_CALL)
				{
					off = *((int *)(codeBytePtr + 2));
					addReloc(hook,codeBytePtr + 2, off, 4);

					if (verbose)
						xprintf("MODRM based CALL found at 0x%p -> RELOFFSET: %x (%d)\n\n", codeBytePtr, off,off);

					//detect size
				}
			}
			break;
			case OC_JCC_NEAR: //two byte len
			{
				//0x80 - 0x8F kosullu dallanma komutlari

				opCode = *(codeBytePtr + 1);

				if (opCode >= OC_JCC_BEGIN && opCode <= OC_JCC_END)
				{
					off = *((int *)(codeBytePtr + 1 + 1));

					addReloc(hook,codeBytePtr + 2, off, 4);

					if (verbose)
						xprintf("REL_JCC found at 0x%p -> RELOFFSET: %x (%d)\n\n", codeBytePtr, off, off);
					
					
					codeBytePtr += 6;
				}
			}
			break;
		}

		codeBytePtr++;
	}

	
	
	requiredFunctionAddress = originalProc - routineCodeSize - 1024;

	newFunc = NULL;

	while (newFunc == NULL)
	{
		//nop alani icin ekstradan 32 byte bellek iste
		newFunc = VirtualAlloc(requiredFunctionAddress, routineCodeSize + 32, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		
		requiredFunctionAddress = ((unsigned char *)requiredFunctionAddress) - 0x1000;

	}

	//Yeni kod bellek bolgesini Nop ile dolduralim cop opcode kalmasin.
	memset(newFunc, 0x90, routineCodeSize + 32);
	
	//orjinal fonksiyon kodunu yeni alana tasiyoruz.
	memcpy(newFunc, originalProc, routineCodeSize);

	//orjinal kod bellek bolgesinin readonly modunu readwrite yapiyoruz.
	if (!VirtualProtect(originalProc, routineCodeSize, PAGE_EXECUTE_READWRITE, &oldProtection))
	{
		xprintf("original code page could not switch to r/w mode");
		VirtualFree(newFunc, routineCodeSize + 32, MEM_RELEASE);

		return NULL;
	}
	
	//orjinal bellek bolgesini nopluyoruz. guvenli olmasi icin
	memset(originalProc, 0x90, routineCodeSize);

	//x64

	//64 bit ise hook fonksiyonumuzun yeri 64 bit araligina giren bir noktada
	//olabilir. o yuzden 64 bit bir registera adresi alip oraya zipliyoruz
	if (is64bit)
	{
		//64 bit trambolin fonksiyon cagrisi

		//mov rax, 64BIT_FUNCTION_ADDRESS
		//jmp rax

		*originalProc = (unsigned char)0x48;
		*(originalProc + 1) = (unsigned char)0xB8;
		*((long long int *)(originalProc + 2)) = (long long int)hookFunction;

		*((unsigned short *)(originalProc + 10)) = 0xe0ff;

	}
	else
	{ 
		//32 bit tramboline cagri
		//32 bit ise normal bir jump ile bolgeye ziplayabiliriz.
		
		//JMP NEW_RELATIVE_OFFSET

		int jmpOffset = ((unsigned char *)originalProc) - hookFunction;


		jmpOffset = -jmpOffset;
		jmpOffset -= 5; //our jmp instruction size


		*originalProc = (unsigned char)0xE9;

		*((int *)(originalProc + 1)) = jmpOffset;
	}

	VirtualProtect(originalProc, routineCodeSize, oldProtection, &oldProtection);


	xprintf("Original Function Location: 0x%p\n", originalProc);
	xprintf("New Function Location: 0x%p\n", newFunc);

	for (relocBranchList *beg = hook->relocList->head; beg != NULL; beg = beg->next)
	{
		recalculateAndPatch(originalProc, (unsigned char *)newFunc, beg->rbi);
	}

	hook->originalApi = newFunc;
	hook->hookFunction = hookFunction;

	return hook;
}


int main()
{
	char *test_data = "BENI KIMSE TUTAMAZ!";
	DWORD written = 0;
	HANDLE fileHandle;

	writeFileHook = hookAPIFunction("kernel32.dll", "WriteFile", (unsigned char *)hooked_WriteFile);
	//hookAPIFunction("kernel32.dll", "CreateFileW", (unsigned char *)hooked_CreateFileW, (void **)&originalCreateFile);

	if (!writeFileHook)
		return 0;

	originalWriteFile = (WriteFilePtr)writeFileHook->originalApi;

	fileHandle = CreateFile(L"D:\\TESTDOSYA.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);

	WriteFile(fileHandle, test_data, strlen(test_data), &written, NULL);

	CloseHandle(fileHandle);
	
}

