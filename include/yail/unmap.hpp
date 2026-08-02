#pragma once
#include <Windows.h>
#include <winternl.h>
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

        namespace scanner
        {
            inline bool pattern_match(const uint8_t* data, const char* pattern)
            {
                for (; *pattern; ++data)
                {
                    if (*pattern == ' ') { ++pattern; --data; continue; }
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

        // Signatures verified via IDA Pro on Windows 11 24H2 (build 26100).

        inline void* find_rtl_remove_inverted_function_table()
        {
            // Verified: ntdll + 0x33134
            return scanner::find_in_module(GetModuleHandleA("ntdll.dll"),
                "40 53 48 83 EC ? 48 8B D9 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B D3 E8");
        }

        inline void* find_ldrp_release_tls_entry()
        {
            // Verified: ntdll + 0xD73C8
            return scanner::find_in_module(GetModuleHandleA("ntdll.dll"),
                "48 89 5C 24 ? 57 48 83 EC ? 48 8B FA 48 8B D9 48 85 D2 75");
        }

        // ---- Trampoline ----

#ifdef _WIN64
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

        [[noreturn]] inline void self_unmap(void* base)
        {
            const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                static_cast<const uint8_t*>(base) + dos->e_lfanew);
            const bool is_dll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

            // 1. DllMain(DLL_PROCESS_DETACH)
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
            if (auto* fn = find_rtl_remove_inverted_function_table())
                reinterpret_cast<RtlRemoveInvertedFunctionTableFn>(fn)(base);

            // 4. LdrpReleaseTlsEntry — use the persistent heap pointer
            // stashed by the injection shellcode at base + sizeof(IMAGE_DOS_HEADER).
            if (auto* fn = find_ldrp_release_tls_entry())
            {
                auto** stash = reinterpret_cast<LdrDataTableEntryFull**>(
                        static_cast<uint8_t*>(base) + sizeof(IMAGE_DOS_HEADER));

                if (tls_dir.Size && *stash)
                {
                    reinterpret_cast<LdrpReleaseTlsEntryFn>(fn)(*stash, nullptr);

                    // Free the persistent heap allocation.
                    auto* ntdll = GetModuleHandleA("ntdll.dll");
                    auto heap = GetProcessHeap();
                    auto rtlFree = reinterpret_cast<BOOLEAN(NTAPI*)(HANDLE, ULONG, PVOID)>(
                            GetProcAddress(ntdll, "RtlFreeHeap"));
                    if (rtlFree)
                        rtlFree(heap, 0, *stash);
                }
            }

            // 5. Free and exit
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
