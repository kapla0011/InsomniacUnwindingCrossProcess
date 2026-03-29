# InsomniacUnwinding

Surgical UNWIND_INFO preservation for sleep masking without call stack spoofing.

**Blog Post:** [Unwind Data Can't Sleep - Introducing InsomniacUnwinding](https://lorenzomeacci.com/unwind-data-cant-sleep-introducing-insomniacunwinding)

## Overview

Traditional sleep masking encrypts the entire beacon image, breaking stack unwinding. Existing solutions (Ekko, Foliage, etc.) rely on timers/APCs which execute in a different thread context, requiring call stack spoofing to appear legitimate.

InsomniacUnwinding POC takes a different approach:
- Cross-process sleep masking keeps the beacon's thread context intact
- Surgical extraction preserves only the `UNWIND_INFO` structures needed for stack walking (~250 bytes vs ~6KB full `.rdata`)
- No call stack spoofing required when both beacon and sleepmask live in backed memory

## Architecture
```
Connects to named pipe
                         SLEEP_REQUEST {PID, ImageBase, ImageSize, SleepTimeMs}
InsomniacUnwinding.exe   <─────────────────────────────────────────────  Beacon-Sample.exe
        │                                                                      │
        │  1. OpenProcess(PID)                                                 │
        │  2. ReadProcessMemory(ImageBase, ImageSize)                          │
        │  3. Save regions: PE Headers + .pdata + UNWIND_INFO (~250 bytes)     │
        │  4. VirtualProtectEx → PAGE_READWRITE                                │
        │  5. SystemFunction032 (encrypt entire image)                         │
        │  6. Patch back preserved regions                                     │
        │                                                                      │
        │                    WriteProcessMemory                                │
        ├─────────────────────────────────────────────>   [ENCRYPTED]          │
        │                                                                      │
        │  7. Sleep(SleepTimeMs)                                 [Blocked on ReadFile]
        │                                                        [Stack intact]
        │  8. SystemFunction032 (decrypt)                        [YARA = 0 hits]
        │  9. Patch back preserved regions                                     │
        │                                                                      │
        │                    WriteProcessMemory                                │
        ├─────────────────────────────────────────────>   [DECRYPTED]          │
        │                                                                      │
        │  10. VirtualProtectEx → PAGE_EXECUTE_READ                            │
        │                                                                      │
        │                    SLEEP_RESPONSE {Success, ErrorCode}               │
        └─────────────────────────────────────────────>                        │
                                                                 [Continues execution]
```

## Usage

1. Build both projects in Visual Studio (x64 Release)

2. Start the sleepmask service:
```
.\InsomniacUnwinding.exe
```

3. In another terminal, run the beacon:
```
.\Beacon-Sample.exe
```

4. The beacon connects to the named pipe and enters the sleep cycle. Inspect the call stack during sleep to verify it resolves correctly through `BaseThreadInitThunk` and `RtlUserThreadStart`.

## YARA Testing

A test YARA rule is included to verify signatures are encrypted during sleep:
```
.\yara64.exe BeaconSignature.yar <beacon_pid>
```

Expected results:
- **Awake:** 2 hits (`DEADBEEF` in `.rdata` and `.data`)
- **Sleeping:** 0 hits (signatures encrypted)

## Implementation

This POC is only used to showcase the power of surgical unwind data preservation. If you want to use this approach in production with a C2, you will have to do some legwork. The code idea is that both beacon and sleepmask must live in backed memory (stomped modules)

## Key Insight

Call stack spoofing is an architectural consequence of unbacked sleepmask memory, not a fundamental requirement. When the sleepmask executes from backed memory, spoofing becomes unnecessary.
