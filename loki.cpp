#undef UNICODE

#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <wchar.h>

#define FUNC_TO_STR(x) #x

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (VOID);


typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;


typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];

	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
} PROCESSINFOCLASS, * PPROCESSINFOCLASS;

typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
	_In_       HANDLE ProcessHandle,
	_In_       PROCESSINFOCLASS ProcessInformationClass,
	_Out_      PVOID ProcessInformation,
	_In_       ULONG ProcessInformationLength,
	_Out_opt_  PULONG ReturnLength
	);

int GetProcessInfo(int pid)
{
	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (ProcessHandle == NULL)
	{
		return TRUE;
	}

	const char* ModuleName = "ntdll.dll";
	const char* ApiName = "NtQueryInformationProcess";

	pNtQueryInformationProcess NtQuery = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA(ModuleName), ApiName);

	PROCESS_BASIC_INFORMATION info;
	ZeroMemory(&info, sizeof(info));

	NtQuery(ProcessHandle, ProcessBasicInformation, &info, sizeof(info), NULL);

	if (info.PebBaseAddress != NULL)
	{
		int IsReadSuccess = FALSE;

		//Read peb
		PEB peb;
		ZeroMemory(&peb, sizeof(peb));
		ReadProcessMemory(ProcessHandle, info.PebBaseAddress, &peb, sizeof(peb), NULL);
		
		//Read first doubly linked list address
		PEB_LDR_DATA link;
		ZeroMemory(&link, sizeof(link));
		ReadProcessMemory(ProcessHandle, peb.Ldr, &link, sizeof(link), NULL);


		//Read Process Image Path Name
		RTL_USER_PROCESS_PARAMETERS ptrmtr;
		UNICODE_STRING ImagePathName;
		ZeroMemory(&ImagePathName, sizeof(ImagePathName));
		IsReadSuccess = ReadProcessMemory(	ProcessHandle, 
											peb.ProcessParameters, 
											&ptrmtr,
											sizeof(ptrmtr),
											NULL);

		WCHAR ProcessName[MAX_PATH * 2];
		ZeroMemory(ProcessName, sizeof(ProcessName));

		IsReadSuccess = ReadProcessMemory(ProcessHandle,
			ptrmtr.ImagePathName.Buffer,
			ProcessName,
			ptrmtr.ImagePathName.Length,
			NULL);

		//Read module info
		BYTE entry[32 + sizeof(LPVOID)];
		BYTE *lpImageBaseAddress = entry;
		ZeroMemory(entry, sizeof(entry));

		ReadProcessMemory(ProcessHandle, link.InMemoryOrderModuleList.Flink, entry, sizeof(entry), NULL);
		
		//64, 32bit process

#ifdef _WIN64
		_IMAGE_NT_HEADERS64 header;
		#define ADDRESS INT64
		ADDRESS address;

		lpImageBaseAddress += 32;
#else 
		_IMAGE_NT_HEADERS header;
		#define ADDRESS INT32
		ADDRESS address;

		lpImageBaseAddress += 16;
#endif // _WIN64

		for (int i = 0; i != sizeof(ADDRESS); i++)
		{
			((BYTE*)&address)[i] = lpImageBaseAddress[i];
		}
		ADDRESS base = address;

		address += 0x3c ;

		BYTE buffer[4];
		ZeroMemory(buffer, sizeof(buffer));
		ReadProcessMemory(ProcessHandle, (LPVOID)address, buffer, sizeof(buffer), NULL);

		address -= 0x3c;

		ADDRESS ExeHeader = 0;

		for (int i = 0; i != sizeof(buffer); i++)
		{
			((BYTE*)&ExeHeader)[i] = buffer[i];
		}

		address += ExeHeader;
		ZeroMemory(&header, sizeof(header));
		ReadProcessMemory(ProcessHandle, (LPVOID)address, &header, sizeof(header), NULL);

		//0x68

		int IAT_Location = 128;//location of IAT from 32bit PEFILE

		ADDRESS ImportAddressTableRVA = 0;
		ReadProcessMemory(ProcessHandle, (LPVOID) (address + IAT_Location), &ImportAddressTableRVA, sizeof(ImportAddressTableRVA), NULL);

		address += sizeof(header);

		IMAGE_SECTION_HEADER ImageSectionHeader;

		for (int i = 0; i != header.FileHeader.NumberOfSections; i++)
		{
			//read section header
			ReadProcessMemory(ProcessHandle, (LPVOID)address, &ImageSectionHeader, sizeof(ImageSectionHeader), NULL);

			const char* SectionName = ".idata";
			const char* ptr = (const char *)ImageSectionHeader.Name;

			//exist .idata section
			if ( memcmp(ptr, SectionName, lstrlen(SectionName)) == 0)
			{
				fputws(ProcessName, stdout);
				printf(":%d\n", pid);


				if (header.OptionalHeader.Magic == 0x10b)
				{
					printf("\t-32bit process\n");
				}

				if (header.OptionalHeader.Magic == 0x20b)
				{
					printf("\t-64bit process\n");
				}
				printf("Number of section:\t%d\n", header.FileHeader.NumberOfSections);

				printf("Section name:\t%s\n", ImageSectionHeader.Name);
				printf("Header RVA:\t%X\n", ImageSectionHeader.VirtualAddress);
				printf("IAT RVA:\t%X\n", ImportAddressTableRVA);

				ADDRESS NamePointerTableRVA = 0;
				ReadProcessMemory(ProcessHandle, (LPVOID) (base + ImportAddressTableRVA), &NamePointerTableRVA, sizeof(NamePointerTableRVA), NULL);
				
				printf("Name Pointer Table RVA:\t%p\n", NamePointerTableRVA);

				if (NamePointerTableRVA == 0)
				{
					break;
				}

				ADDRESS ApiName = 0;
				BYTE ApiNameBuffer[32];

				for (;;)
				{
					ReadProcessMemory(ProcessHandle, (LPVOID)(base + NamePointerTableRVA), &ApiName, sizeof(ApiName), NULL);
					if (ApiName == 0)
					{
						break;
					}

					int index = 0;
					for (;;)
					{
						ReadProcessMemory(ProcessHandle, (LPVOID)(base + ApiName + index), &ApiNameBuffer[index], sizeof(ApiNameBuffer[index]), NULL);
						
						if (ApiNameBuffer[index] == 0)
						{
							break;
						}

						index++;
					}

					if (ApiNameBuffer[0] != 0)
					{
						printf("%s\n", ApiNameBuffer + sizeof(SHORT));
					}

					NamePointerTableRVA += sizeof(ADDRESS);
				}

				printf("\n\n");
			}

			address += sizeof(ImageSectionHeader);
		}
	}

	CloseHandle(ProcessHandle);

	return 0;
}

int main()
{
	SetConsoleTitleA("project loki (dev: woohyuk seo)");

	printf("\n");

	PROCESSENTRY32 ProcessInfo;
	ProcessInfo.dwSize = sizeof(ProcessInfo);

	HANDLE SnapShotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (SnapShotHandle == INVALID_HANDLE_VALUE)
	{
		printf("[!] %s\n", FUNC_TO_STR(CreateToolhelp32Snapshot));
		return 0;
	}

	if (Process32First(SnapShotHandle, &ProcessInfo) == FALSE)
	{
		printf("[!] %s\n", FUNC_TO_STR(Process32First));
		CloseHandle(SnapShotHandle);
		return 0;
	}

	for (;;)
	{
		if (Process32Next(SnapShotHandle, &ProcessInfo) == FALSE)
		{
			break;
		}
		else
		{
			GetProcessInfo(ProcessInfo.th32ProcessID);
		}
	}

	CloseHandle(SnapShotHandle);

	return 0;
}