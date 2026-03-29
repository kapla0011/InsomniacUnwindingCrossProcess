// this is just used to simulate beacon being overloaded somewhere whit its unwind data registered
#include <iostream>
#include <windows.h>

#define SLEEPMASK_PIPE_NAME L"\\\\.\\pipe\\sleepmask_channel"

typedef struct _SLEEP_REQUEST {
	DWORD  ProcessId;
	DWORD  SleepTimeMs;
	ULONG_PTR ImageBase;
	DWORD  ImageSize;
} SLEEP_REQUEST, * PSLEEP_REQUEST;

typedef struct _SLEEP_RESPONSE {
	BOOL   Success;
	DWORD  ErrorCode;
} SLEEP_RESPONSE, * PSLEEP_RESPONSE;

void GetImageInfo(ULONG_PTR* pBase, DWORD* pSize) {
	*pBase = (ULONG_PTR)GetModuleHandleA(NULL);
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(*pBase +
		((PIMAGE_DOS_HEADER)*pBase)->e_lfanew);
	*pSize = pNtHdrs->OptionalHeader.SizeOfImage;
}

//signature bytes that are scanned with yara. To make this array fall back in .rdata it needs to be a const 
const char array_rdata[] = { 0xDE, 0xAD, 0xBE, 0xEF };

// to make it fall in .data it needs to be a non const 
char array2_data[] = { 0xDE, 0xAD, 0xBE, 0xEF };

BOOL RequestEncryption(DWORD SleepTimeMs) {
	HANDLE pipe;
	DWORD bytesWritten, bytesRead;
	SLEEP_REQUEST request = { 0 };
	SLEEP_RESPONSE response = { 0 };

	puts("[*] Connecting to sleepmask...");
	// Connect to the named pipe
	pipe = CreateFileW(SLEEPMASK_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (pipe == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to connect to the pipe. Error: " << GetLastError() << std::endl;
		return FALSE;
	}

	puts("[*] Connected to sleepmask, preparing request...");
	// Prepare the request
	request.ProcessId = GetCurrentProcessId();
	request.SleepTimeMs = SleepTimeMs;
	GetImageInfo(&request.ImageBase, &request.ImageSize);

	printf("[*] Requesting sleep mask: PID=%lu, Base=0x%p, Size=%lu, Time=%lums\n",
		request.ProcessId, (PVOID)request.ImageBase, request.ImageSize, request.SleepTimeMs);

	puts("[*] Sending request to sleepmask...");
	// Send the request
	if (!WriteFile(pipe, &request, sizeof(request), &bytesWritten, NULL)) {
		std::cerr << "Failed to write to the pipe. Error: " << GetLastError() << std::endl;
		CloseHandle(pipe);
		return FALSE;
	}

	// Wait for the response
	// We are now sleeping
	puts("[*] Waiting for sleepmask response...");
	if (!ReadFile(pipe, &response, sizeof(response), &bytesRead, NULL)) {
		std::cerr << "Failed to read from the pipe. Error: " << GetLastError() << std::endl;
		CloseHandle(pipe);
		return FALSE;
	}

	CloseHandle(pipe);
	if (response.Success = TRUE) {
		printf("[*] Sleep mask applied successfully.\n");
	}
	else {
		std::cerr << "Failed to apply sleep mask. Error code: " << response.ErrorCode << std::endl;
	}

}

int main()
{
	//use the arrays or they will not be included in the final (due to optimization) binary and thus not be scanned by yara.
	for (int i = 0; i < sizeof(array_rdata); i++) {

		//use the array in .rdata
		int b = array_rdata[i];

		//use the array in .data
		int c = array2_data[i];

	}
	puts("[*] This is a simple executable used to mimic an overloaded beacon");
	int process_id = GetCurrentProcessId();
	printf("[*] Scan for yara at PID: %d\n", process_id);
	puts("[*] click enter to start...");
	getchar();
	int seconds = 10;
	int milliseconds = seconds * 1000;
	do {
		RequestEncryption(milliseconds);
		puts("[*] Check the call stack now that that the image is decrypted... then click enter");
		getchar();
	} while (true);
	return 0;

}

