#pragma once
#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace yail
{
    namespace detail_unmap
    {
        struct LdrDataTableEntryFull final
        {
            LIST_ENTRY in_load_order_links;
            LIST_ENTRY in_memory_order_links;
            LIST_ENTRY in_initialization_order_links;
            PVOID dll_base;
            PVOID entry_point;
            ULONG size_of_image;
            [[maybe_unused]] UNICODE_STRING full_dll_name;
            [[maybe_unused]] UNICODE_STRING base_dll_name;
            [[maybe_unused]] ULONG flags;
            [[maybe_unused]] USHORT obsolete_load_count;
            [[maybe_unused]] USHORT tls_index;
            LIST_ENTRY hash_links;
            [[maybe_unused]] ULONG time_date_stamp;
        };

#ifdef _WIN64
        using RtlRemoveInvertedFunctionTableFn = void(NTAPI*)(PVOID image_base);
        using LdrpReleaseTlsEntryFn = NTSTATUS(NTAPI*)(LdrDataTableEntryFull*, PVOID);
#else
        using RtlRemoveInvertedFunctionTableFn = void(__fastcall*)(PVOID image_base);
        using LdrpReleaseTlsEntryFn = NTSTATUS(__fastcall*)(LdrDataTableEntryFull*, PVOID);
#endif

        // ---- Minimal pattern scanner ----

        namespace scanner
        {
            inline bool pattern_match(const uint8_t* data, const char* pattern)
            {
                for (; *pattern; ++data)
                {
                    if (*pattern == ' ') { ++pattern; continue; }
                    if (*pattern == '?') { ++pattern; continue; }
                    const char hi = *pattern++;
                    const char lo = *pattern++;
                    if (!hi || !lo) return false;
                    const auto expected = static_cast<uint8_t>(
                        ((hi >= 'A' ? hi - 'A' + 10 : hi - '0') << 4) |
                        (lo >= 'A' ? lo - 'A' + 10 : lo - '0'));
                    if (*data != expected) return false;
                }
                return true;
            }

            inline std::size_t pattern_length(const char* pattern)
            {
                std::size_t len = 0;
                for (; *pattern; ++pattern)
                {
                    if (*pattern == ' ' || *pattern == '?') continue;
                    ++pattern;
                    ++len;
                }
                return len;
            }

            inline void* find_in_module(HMODULE mod, const char* pattern)
            {
                if (!mod || !pattern || !*pattern) return nullptr;
                const auto plen = pattern_length(pattern);
                if (!plen) return nullptr;

                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                    reinterpret_cast<const uint8_t*>(mod) + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

                const auto* section = IMAGE_FIRST_SECTION(nt);
                for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
                {
                    char name[9]{}; std::memcpy(name, section->Name, 8);
                    if (std::strcmp(name, ".text") != 0) continue;
                    const auto* begin = reinterpret_cast<const uint8_t*>(mod) + section->VirtualAddress;
                    const auto* end = begin + section->Misc.VirtualSize - plen;
                    for (const auto* cur = begin; cur <= end; ++cur)
                        if (pattern_match(cur, pattern))
                            return const_cast<uint8_t*>(cur);
                    break;
                }
                return nullptr;
            }
        } // namespace scanner

        // ---- Internal-pattern + walk-backwards finder (NimRunPE/Blackbone technique) ----
        // Finds a pattern inside the function body, then walks backwards through
        // 0xCC alignment padding to find the actual function prologue.

        inline void* find_func_by_internal_pattern(const char* pattern)
        {
            auto* ntdll = GetModuleHandleA("ntdll.dll");
            if (!ntdll) return nullptr;
            const auto plen = scanner::pattern_length(pattern);
            if (!plen) return nullptr;

            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdll);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                reinterpret_cast<const uint8_t*>(ntdll) + dos->e_lfanew);

            const auto* section = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
            {
                char name[9]{}; std::memcpy(name, section->Name, 8);
                if (std::strcmp(name, ".text") != 0) continue;
                const auto* begin = reinterpret_cast<const uint8_t*>(ntdll) + section->VirtualAddress;
                const auto* end = begin + section->Misc.VirtualSize - plen;

                for (const auto* cur = begin; cur <= end; ++cur)
                {
                    if (!scanner::pattern_match(cur, pattern)) continue;
                    const auto* func = cur;
                    for (int step = 0; step < 0x200 && func > begin; ++step)
                    {
                        --func;
                        if (*func != 0xCC) break;
                    }
                    return const_cast<uint8_t*>(func);
                }
                break;
            }
            return nullptr;
        }

        // ---- PDB fallback ----

        inline void* find_symbol_in_ntdll(const char* name)
        {
            const HMODULE dbghelp = LoadLibraryA("DbgHelp.dll");
            if (!dbghelp) return nullptr;
            auto pSymInit = reinterpret_cast<BOOL(WINAPI*)(HANDLE, PCSTR, BOOL)>(
                GetProcAddress(dbghelp, "SymInitialize"));
            auto pSymName = reinterpret_cast<BOOL(WINAPI*)(HANDLE, PCSTR, PSYMBOL_INFO)>(
                GetProcAddress(dbghelp, "SymFromName"));
            auto pSymSetPath = reinterpret_cast<BOOL(WINAPI*)(HANDLE, PCWSTR)>(
                GetProcAddress(dbghelp, "SymSetSearchPathW"));
            if (!pSymName || !pSymInit) return nullptr;
            pSymInit(GetCurrentProcess(), nullptr, FALSE);
            if (pSymSetPath)
                pSymSetPath(GetCurrentProcess(),
                            L"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols");
            char buf[256];
            snprintf(buf, sizeof(buf), "ntdll!%s", name);
            alignas(SYMBOL_INFO) uint8_t sbuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
            auto* sym = reinterpret_cast<SYMBOL_INFO*>(sbuf);
            sym->SizeOfStruct = sizeof(SYMBOL_INFO);
            sym->MaxNameLen = MAX_SYM_NAME;
            if (pSymName(GetCurrentProcess(), buf, sym))
                return reinterpret_cast<void*>(sym->Address);
            return nullptr;
        }

        // ---- Accessors: three-tier resolution ----

        // Working pattern for RtlInsertInvertedFunctionTable (from yail native_loader.cpp).
        inline void* find_insert_func()
        {
            auto* ntdll = GetModuleHandleA("ntdll.dll");
            constexpr std::array<const char*, 3> sigs = {
                "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 48 83 EC ? 83 60",
                "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 8B FA",
                "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC",
            };
            for (const auto* s : sigs)
                if (auto* r = scanner::find_in_module(ntdll, s))
                    return r;
            return nullptr;
        }

        inline void* find_rtl_remove_inverted_function_table()
        {
            auto* ntdll = GetModuleHandleA("ntdll.dll");
            if (!ntdll) return nullptr;

            // Tier 1: internal pattern from RtlpRemoveInvertedFunctionTable search loop
            // (cmp ImageBase against table entry)
            {
                constexpr const char* internal_sigs[] = {
                    "48 8B 4B ? 48 39 01 75",
                    "48 3B D8 75 ? 48 8B",
                    "4C 39 ? ? ? 75 ? 48 8B",
                };
                for (const auto* s : internal_sigs)
                    if (auto* r = find_func_by_internal_pattern(s))
                        return r;
            }

            // Tier 2: standard prologue patterns in .text
            {
                constexpr std::array<const char*, 5> sigs = {
                    "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 48 83 EC ? 48 8B FA",
                    "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 8B FA",
                    "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B",
                    "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 33",
                    "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B",
                };
                for (const auto* s : sigs)
                    if (auto* r = scanner::find_in_module(ntdll, s))
                        return r;
            }

            // Tier 3: find insert function (known working), scan nearby
            if (auto* insert = find_insert_func())
            {
                constexpr std::array<const char*, 3> nearby = {
                    "48 89 5C 24 ? 57 48 83 EC ? 48 8B",
                    "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC",
                };
                for (const auto* s : nearby)
                {
                    const auto plen = scanner::pattern_length(s);
                    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdll);
                    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                        reinterpret_cast<const uint8_t*>(ntdll) + dos->e_lfanew);
                    const auto* mod_end = reinterpret_cast<const uint8_t*>(ntdll)
                                          + nt->OptionalHeader.SizeOfImage;
                    constexpr std::ptrdiff_t range = 0x2000;
                    auto* start = reinterpret_cast<const uint8_t*>(insert) - range;
                    if (start < reinterpret_cast<const uint8_t*>(ntdll))
                        start = reinterpret_cast<const uint8_t*>(ntdll);
                    auto* end_scan = reinterpret_cast<const uint8_t*>(insert) + range;
                    if (end_scan > mod_end) end_scan = mod_end;
                    for (auto* cur = start; cur + plen <= end_scan; ++cur)
                        if (scanner::pattern_match(cur, s))
                            return const_cast<uint8_t*>(cur);
                }
            }

            return find_symbol_in_ntdll("RtlRemoveInvertedFunctionTable");
        }

        inline void* find_ldrp_release_tls_entry()
        {
            auto* ntdll = GetModuleHandleA("ntdll.dll");
            if (!ntdll) return nullptr;

            // Tier 1: proven internal pattern from NimRunPE / Blackbone / landaire.net
            //   and   ecx, 7
            //   shr   rdx, 3
            // Located inside LdrpReleaseTlsEntry (bit-test for TLS index bitmap).
            if (auto* r = find_func_by_internal_pattern("83 E1 07 48 C1 EA 03"))
                return r;

            // Tier 2: standard prologue patterns
            {
                constexpr std::array<const char*, 5> sigs = {
                    "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 41 ? 48 8B",
                    "48 8B C4 48 89 58 ? 48 89 70 ? 57 48 83 EC ? 48 8B 41",
                    "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 48 8B",
                    "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 48 83 EC ? 48 8B 41",
                    "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 41",
                };
                for (const auto* s : sigs)
                    if (auto* r = scanner::find_in_module(ntdll, s))
                        return r;
            }

            return find_symbol_in_ntdll("LdrpReleaseTlsEntry");
        }

        // ---- Trampoline ----

#ifdef _WIN64
        // x64: raw byte array trampoline. Uses callee-saved registers to survive
        // across the NtFreeVirtualMemory call, then calls RtlExitUserThread(0).
        inline constexpr std::array<uint8_t, 45> kUnmapTrampolineX64{{
            0x53,                                        // push rbx
            0x57,                                        // push rdi
            0x56,                                        // push rsi
            0x48, 0x8B, 0x59, 0x10,                     // mov rbx, [rcx+0x10]
            0x48, 0x8B, 0x79, 0x18,                     // mov rdi, [rcx+0x18]
            0x48, 0x8B, 0xF1,                           // mov rsi, rcx
            0x48, 0x83, 0xE4, 0xF0,                     // and rsp, -16
            0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 0x28
            0x48, 0x83, 0xC9, 0xFF,                     // or rcx, -1
            0x48, 0x8D, 0x16,                           // lea rdx, [rsi]
            0x4C, 0x8D, 0x46, 0x08,                     // lea r8, [rsi+0x08]
            0x41, 0xB9, 0x00, 0x80, 0x00, 0x00,         // mov r9d, 0x8000
            0xFF, 0xD3,                                  // call rbx
            0x33, 0xC9,                                  // xor ecx, ecx
            0xFF, 0xD7,                                  // call rdi
        }};

        [[noreturn]] inline void invoke_trampoline(void* base, void* nt_free_vm, void* rtl_exit)
        {
            alignas(16) uint8_t ctx[32]{};
            *reinterpret_cast<void**>(ctx + 0x00) = base;
            *reinterpret_cast<void**>(ctx + 0x08) = nullptr;
            *reinterpret_cast<void**>(ctx + 0x10) = nt_free_vm;
            *reinterpret_cast<void**>(ctx + 0x18) = rtl_exit;

            auto* trampoline = static_cast<void(NTAPI*)(void*)>(VirtualAlloc(
                nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (!trampoline) __fastfail(1);
            std::memcpy(trampoline, kUnmapTrampolineX64.data(), kUnmapTrampolineX64.size());
            trampoline(ctx);
        }
#else
        __declspec(naked) void __stdcall invoke_trampoline_x86(
            void* base, void* nt_free_vm, void* rtl_exit)
        {
            __asm {
                push ebp
                mov ebp, esp
                sub esp, 8
                xor eax, eax
                mov[ebp - 8], eax
                mov eax, [ebp + 8]
                mov[ebp - 4], eax
                push 0
                push 08000h
                lea eax, [ebp - 8]
                push eax
                lea eax, [ebp - 4]
                push eax
                xor eax, eax
                dec eax
                push eax
                push[ebp + 16]
                jmp[ebp + 12]
            }
        }

        [[noreturn]] inline void invoke_trampoline(void* base, void* nt_free_vm, void* rtl_exit)
        {
            invoke_trampoline_x86(base, nt_free_vm, rtl_exit);
        }
#endif

        // ---- Main entry point ----

        [[noreturn]] inline void self_unmap(void* base)
        {
            const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                static_cast<const uint8_t*>(base) + dos->e_lfanew);
            const bool is_dll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

            fprintf(stderr, "[yail::unmap] begin base=%p\n", base); fflush(stderr);

            // 1. DllMain(DLL_PROCESS_DETACH)
            fprintf(stderr, "[yail::unmap] step1: DllMain(DETACH)\n"); fflush(stderr);
            if (is_dll && nt->OptionalHeader.AddressOfEntryPoint)
            {
                auto ep = reinterpret_cast<BOOL(WINAPI*)(HMODULE, DWORD, LPVOID)>(
                    static_cast<uint8_t*>(base) + nt->OptionalHeader.AddressOfEntryPoint);
                ep(static_cast<HMODULE>(base), DLL_PROCESS_DETACH, nullptr);
            }

            // 2. TLS callbacks(DLL_PROCESS_DETACH)
            const auto& tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tls_dir.Size)
            {
                auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(
                    static_cast<const uint8_t*>(base) + tls_dir.VirtualAddress);
                auto* cbs = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
                for (; cbs && *cbs; ++cbs)
                    (*cbs)(base, DLL_PROCESS_DETACH, nullptr);
            }

            // 3. RtlRemoveInvertedFunctionTable
            fprintf(stderr, "[yail::unmap] step3: RtlRemoveInvertedFunctionTable\n"); fflush(stderr);
            if (auto* fn = find_rtl_remove_inverted_function_table())
            {
                fprintf(stderr, "[yail::unmap]   -> found at %p\n", fn); fflush(stderr);
                reinterpret_cast<RtlRemoveInvertedFunctionTableFn>(fn)(base);
            }
            else
            {
                fprintf(stderr, "[yail::unmap]   -> NOT FOUND\n"); fflush(stderr);
            }

            // 4. LdrpReleaseTlsEntry
            fprintf(stderr, "[yail::unmap] step4: LdrpReleaseTlsEntry\n"); fflush(stderr);
            if (tls_dir.Size)
            {
                if (auto* fn = find_ldrp_release_tls_entry())
                {
                    fprintf(stderr, "[yail::unmap]   -> found at %p\n", fn); fflush(stderr);
                    LdrDataTableEntryFull fake{};
                    auto* raw = reinterpret_cast<volatile uint8_t*>(&fake);
                    for (std::size_t i = 0; i < sizeof(fake); ++i) raw[i] = 0;
                    fake.dll_base = base;
                    fake.size_of_image = nt->OptionalHeader.SizeOfImage;
                    fake.entry_point = static_cast<uint8_t*>(base)
                                       + nt->OptionalHeader.AddressOfEntryPoint;
                    fake.in_load_order_links.Flink = &fake.in_load_order_links;
                    fake.in_load_order_links.Blink = &fake.in_load_order_links;
                    fake.in_memory_order_links.Flink = &fake.in_memory_order_links;
                    fake.in_memory_order_links.Blink = &fake.in_memory_order_links;
                    fake.in_initialization_order_links.Flink = &fake.in_initialization_order_links;
                    fake.in_initialization_order_links.Blink = &fake.in_initialization_order_links;
                    fake.hash_links.Flink = &fake.hash_links;
                    fake.hash_links.Blink = &fake.hash_links;
                    reinterpret_cast<LdrpReleaseTlsEntryFn>(fn)(&fake, nullptr);
                }
                else
                {
                    fprintf(stderr, "[yail::unmap]   -> NOT FOUND\n"); fflush(stderr);
                }
            }
            else
            {
                fprintf(stderr, "[yail::unmap]   -> no TLS directory\n"); fflush(stderr);
            }

            // 5. Free and exit
            fprintf(stderr, "[yail::unmap] step5: free and exit\n"); fflush(stderr);
            auto* ntdll = GetModuleHandleA("ntdll.dll");
            auto* ntfv = GetProcAddress(ntdll, "NtFreeVirtualMemory");
            auto* reut = GetProcAddress(ntdll, "RtlExitUserThread");
            if (!ntfv || !reut) __fastfail(2);
            invoke_trampoline(base, ntfv, reut);
        }
    } // namespace detail_unmap

    [[noreturn]] inline void self_unmap(void* base)
    {
        detail_unmap::self_unmap(base);
    }
} // namespace yail
