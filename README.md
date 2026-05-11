# Tenzo X DSI

direct syscall injector for x64 windows. manual maps a DLL into a target process without touching any hooked APIs.

## how it works

instead of calling `LoadLibrary` or `CreateRemoteThread` through the normal win32 API (where every EDR and their mother has hooks), this does everything through raw `syscall` instructions. the SSNs get resolved at runtime from ntdll so it works across windows versions.

**the pipeline:**
1. resolve syscall numbers from ntdll (with halo's gate fallback if they're hooked)
2. allocate RWX memory in target via `NtAllocateVirtualMemory` — skips `NtProtectVirtualMemory` entirely
3. manually map PE sections + headers
4. inject shellcode that handles relocations, imports, TLS, SEH, then calls DllMain
5. clean up shellcode, wipe PE headers from remote memory

no LDR entry gets created. no `LoadLibrary` call. PE headers get zeroed so there's no MZ/PE signature to scan for.

## building

open `TenzoXDSI.sln` in visual studio 2022. build for x64 (Debug or Release). thats it.

needs MASM enabled which the project already configures.

## usage

you can either pass args directly:
```
TenzoXDSI.exe notepad.exe C:\path\to\your.dll
TenzoXDSI.exe 1234 payload.dll
```

or just run it with no args for the interactive menu:
```
TenzoXDSI.exe
```
it'll let you pick a process and DLL path from a prompt.

## what it bypasses

- **API hooks** — never calls kernel32/ntdll exports, goes straight to syscall
- **LoadLibrary monitoring** — manual PE mapping, no loader involvement
- **module enumeration** — no PEB/LDR entry for the injected DLL
- **NtProtectVirtualMemory hooks** — allocates as RWX from the start
- **PE scanning** — headers get wiped post-injection
- **address prediction** — randomized base address allocation

## project structure

```
TenzoXDSI.cpp    — everything (syscall init, injector, console UI)
TenzoXDSI.asm    — x64 syscall stubs
TenzoXDSI.sln    — VS2022 solution
TenzoXDSI.vcxproj
```

kept it as a single cpp + asm on purpose. no reason to split this into 15 files.

## notes

- x64 only. no x86 support planned
- needs admin if the target process is elevated
- tested on windows 10/11
- for educational / research purposes

## license

MIT
