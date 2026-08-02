#pragma once
#include <Windows.h>
#include <winternl.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace yail
{
    namespace detail_unmap
    {
        // LDR_DATA_TABLE_ENTRY subset — only what LdrpReleaseTlsEntry reads.
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

        // ---- Minimal pattern scanner (no omath dependency) ----

        namespace scanner
        {
            inline bool pattern_match(const uint8_t* data, const char* pattern)
            {
                for (; *pattern; ++data)
                {
                    if (*pattern == ' ')
                    {
                        ++pattern;
                        continue;
                    }
                    if (*pattern == '?')
                    {
                        pattern += (*pattern == '?') ? 1 : 0;
                        continue;
                    }
                    const char high_nibble = *pattern++;
                    const char low_nibble = *pattern++;
                    if (!high_nibble || !low_nibble)
                        return false;
                    const auto expected =
                            static_cast<uint8_t>(((high_nibble >= 'A' ? high_nibble - 'A' + 10 : high_nibble - '0')
                                                  << 4)
                                                 | (low_nibble >= 'A' ? low_nibble - 'A' + 10 : low_nibble - '0'));
                    if (*data != expected)
                        return false;
                }
                return true;
            }

            inline std::size_t pattern_length(const char* pattern)
            {
                std::size_t len = 0;
                for (; *pattern; ++pattern)
                {
                    if (*pattern == ' ')
                        continue;
                    if (*pattern == '?')
                        continue;
                    ++pattern; // skip second nibble char
                    ++len;
                }
                return len;
            }

            inline void* find_in_module(HMODULE mod, const char* pattern)
            {
                if (!mod || !pattern || !*pattern)
                    return nullptr;

                const auto pattern_len = pattern_length(pattern);
                if (pattern_len == 0)
                    return nullptr;

                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                    return nullptr;

                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                        reinterpret_cast<const uint8_t*>(mod) + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE)
                    return nullptr;

                const auto* section = IMAGE_FIRST_SECTION(nt);
                for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
                {
                    char name[9]{};
                    std::memcpy(name, section->Name, 8);
                    if (std::strcmp(name, ".text") != 0)
                        continue;

                    const auto* begin =
                            reinterpret_cast<const uint8_t*>(mod) + section->VirtualAddress;
                    const auto* end = begin + section->Misc.VirtualSize - pattern_len;

                    for (const auto* cursor = begin; cursor <= end; ++cursor)
                    {
                        if (pattern_match(cursor, pattern))
                            return const_cast<uint8_t*>(cursor);
                    }
                    break;
                }
                return nullptr;
            }
        } // namespace scanner

        // ---- Signature scanning for unload functions ----

        inline void* find_rtl_remove_inverted_function_table()
        {
            constexpr std::array<const char*, 6> signatures = {
#ifdef _WIN64
                // Verified on Windows 11 24H2/25H2.
                "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 48 83 EC ? 48 8B FA",
                "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 8B FA",
                "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B",
#else
                // Verified on Windows 11 24H2 x86 ntdll (__fastcall).
                "8B FF 56 68 ? ? ? ? 8B F1 E8 ? ? ? ? 8B D6 E8",
                "8B FF 51 56 57 BF ? ? ? ? 8B F1 57 E8 ? ? ? ?",
                "8B FF 53 56 57 68 ? ? ? ? 8B D9 E8 ? ? ? ? 8B 35",
#endif
            };

            auto* ntdll = GetModuleHandleA("ntdll.dll");
            for (const auto* sig : signatures)
            {
                if (auto* result = scanner::find_in_module(ntdll, sig))
                    return result;
            }
            return nullptr;
        }

        inline void* find_ldrp_release_tls_entry()
        {
            constexpr std::array<const char*, 6> signatures = {
#ifdef _WIN64
                // Verified on Windows 11 24H2/25H2.
                "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 41 ? 48 8B",
                "48 8B C4 48 89 58 ? 48 89 70 ? 57 48 83 EC ? 48 8B 41",
                "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 48 8B",
#else
                // x86 patterns — best effort.
                "8B FF 55 8B EC 51 56 8B 75 ? 57 8B",
                "8B FF 55 8B EC 83 EC ? 53 56 8B 75 ? 57 8B",
                "55 8B EC 83 EC ? 53 56 8B 75 ? 57 8B",
#endif
            };

            auto* ntdll = GetModuleHandleA("ntdll.dll");
            for (const auto* sig : signatures)
            {
                if (auto* result = scanner::find_in_module(ntdll, sig))
                    return result;
            }
            return nullptr;
        }

        // ---- Trampoline: NtFreeVirtualMemory -> RtlExitUserThread (never returns to DLL) ----

#ifdef _WIN64
        // x64: MSVC does not support inline __asm. The trampoline is a raw byte array
        // built by the self_unmap function on the caller's stack before a tail-call.
        //
        // The trampoline expects a context structure (aligned to 16 bytes):
        //   [0x00] void*  image_base
        //   [0x08] SIZE_T region_size (caller zeroes)
        //   [0x10] void*  NtFreeVirtualMemory
        //   [0x18] void*  RtlExitUserThread
        //
        // On entry, RCX = &context.
        // The trampoline chains NtFreeVirtualMemory -> RtlExitUserThread on the stack
        // by pushing RtlExitUserThread as the return address, then jmp'ing to NtFreeVirtualMemory.
        // NtFreeVirtualMemory frees the DLL; RtlExitUserThread terminates the thread.
        inline constexpr std::array<uint8_t, 45> kUnmapTrampolineX64{{
                // mov rax, [rcx+0x10]     ; rax = NtFreeVirtualMemory
                0x48, 0x8B, 0x41, 0x10,
                // mov r10, [rcx+0x18]     ; r10 = RtlExitUserThread
                0x4C, 0x8B, 0x51, 0x18,
                // and rsp, -16            ; align stack
                0x48, 0x83, 0xE4, 0xF0,
                // sub rsp, 0x28           ; shadow space
                0x48, 0x83, 0xEC, 0x28,
                // push r10                ; RtlExitUserThread as return address for NtFreeVirtualMemory
                0x41, 0x52,
                // lea rdx, [rcx]          ; rdx = &image_base (context[0])
                0x48, 0x8D, 0x11,
                // lea r8, [rcx+0x08]      ; r8 = &region_size (context[1])
                0x4C, 0x8D, 0x41, 0x08,
                // mov r9d, 0x8000         ; r9 = MEM_RELEASE
                0x41, 0xB9, 0x00, 0x80, 0x00, 0x00,
                // or rcx, -1              ; rcx = GetCurrentProcess() pseudo-handle
                0x48, 0x83, 0xC9, 0xFF,
                // jmp rax                 ; tail-call NtFreeVirtualMemory
                0xFF, 0xE0,
        }};

        [[noreturn]] inline void invoke_trampoline(void* base, void* nt_free_vm, void* rtl_exit_thread)
        {
            alignas(16) uint8_t ctx[32]{};
            *reinterpret_cast<void**>(ctx + 0x00) = base;
            *reinterpret_cast<void**>(ctx + 0x08) = nullptr; // region_size = 0
            *reinterpret_cast<void**>(ctx + 0x10) = nt_free_vm;
            *reinterpret_cast<void**>(ctx + 0x18) = rtl_exit_thread;

            const auto trampoline =
                    reinterpret_cast<void(NTAPI*)(void*)>(VirtualAlloc(
                            nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (!trampoline)
                __fastfail(1);

            std::memcpy(reinterpret_cast<void*>(trampoline), kUnmapTrampolineX64.data(),
                        kUnmapTrampolineX64.size());

            trampoline(ctx);
        }
#else
        // x86: MSVC supports inline __asm for stack-chain trampoline.
        // On entry: [esp] = return addr (ignored), [esp+4] = base, [esp+8] = ntFreeVirtualMemory,
        //           [esp+12] = rtlExitUserThread
        // The function chains NtFreeVirtualMemory -> RtlExitUserThread on the stack
        // and never returns to the DLL.
        __declspec(naked) void __stdcall invoke_trampoline_x86(
                void* base, void* nt_free_vm, void* rtl_exit_thread)
        {
            __asm {
                push ebp
                mov ebp, esp
                sub esp, 8                          // locals: [ebp-4] = base_copy, [ebp-8] = region_size(0)
                xor eax, eax
                mov [ebp-8], eax                    // region_size = 0
                mov eax, [ebp+8]                    // base (arg 1)
                mov [ebp-4], eax                    // base_copy

                // Build NtFreeVirtualMemory stack frame with
                // RtlExitUserThread as the return address.
                push 0                              // ExitStatus for RtlExitUserThread
                push 08000h                         // FreeType = MEM_RELEASE
                lea eax, [ebp-8]
                push eax                            // &RegionSize
                lea eax, [ebp-4]
                push eax                            // &BaseAddress
                xor eax, eax
                dec eax
                push eax                            // ProcessHandle = -1
                push [ebp+16]                       // RtlExitUserThread -> becomes NtFreeVirtualMemory ret addr

                jmp [ebp+12]                        // tail-call NtFreeVirtualMemory
            }
        }

        [[noreturn]] inline void invoke_trampoline(void* base, void* nt_free_vm, void* rtl_exit_thread)
        {
            invoke_trampoline_x86(base, nt_free_vm, rtl_exit_thread);
        }
#endif

        // ---- Main self-unmap entry point ----

        [[noreturn]] inline void self_unmap(void* base)
        {
            const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                    static_cast<const uint8_t*>(base) + dos->e_lfanew);

            const bool is_dll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

            // 1. Call DllMain(DLL_PROCESS_DETACH) — reverse of attach order (Blackbone convention)
            if (is_dll && nt->OptionalHeader.AddressOfEntryPoint)
            {
                const auto entry_point = reinterpret_cast<BOOL(WINAPI*)(HMODULE, DWORD, LPVOID)>(
                        static_cast<uint8_t*>(base) + nt->OptionalHeader.AddressOfEntryPoint);
                entry_point(static_cast<HMODULE>(base), DLL_PROCESS_DETACH, nullptr);
            }

            // 2. Call TLS callbacks with DLL_PROCESS_DETACH
            const auto& tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tls_dir.Size)
            {
                const auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(
                        static_cast<const uint8_t*>(base) + tls_dir.VirtualAddress);
                const auto* callbacks =
                        reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
                for (; callbacks && *callbacks; ++callbacks)
                    (*callbacks)(base, DLL_PROCESS_DETACH, nullptr);
            }

            // 3. Remove from inverted function table
            if (const auto fn_remove = find_rtl_remove_inverted_function_table())
            {
                reinterpret_cast<RtlRemoveInvertedFunctionTableFn>(fn_remove)(base);
            }

            // 4. Deregister static TLS
            if (tls_dir.Size)
            {
                if (const auto fn_release_tls = find_ldrp_release_tls_entry())
                {
                    LdrDataTableEntryFull fake_entry{};
                    auto* raw = reinterpret_cast<volatile uint8_t*>(&fake_entry);
                    for (std::size_t i = 0; i < sizeof(fake_entry); ++i)
                        raw[i] = 0;

                    fake_entry.dll_base = base;
                    fake_entry.size_of_image = nt->OptionalHeader.SizeOfImage;
                    fake_entry.entry_point =
                            static_cast<uint8_t*>(base) + nt->OptionalHeader.AddressOfEntryPoint;

                    fake_entry.in_load_order_links.Flink = &fake_entry.in_load_order_links;
                    fake_entry.in_load_order_links.Blink = &fake_entry.in_load_order_links;
                    fake_entry.in_memory_order_links.Flink = &fake_entry.in_memory_order_links;
                    fake_entry.in_memory_order_links.Blink = &fake_entry.in_memory_order_links;
                    fake_entry.in_initialization_order_links.Flink =
                            &fake_entry.in_initialization_order_links;
                    fake_entry.in_initialization_order_links.Blink =
                            &fake_entry.in_initialization_order_links;
                    fake_entry.hash_links.Flink = &fake_entry.hash_links;
                    fake_entry.hash_links.Blink = &fake_entry.hash_links;

#ifdef _WIN64
                    reinterpret_cast<LdrpReleaseTlsEntryFn>(fn_release_tls)(&fake_entry, nullptr);
#else
                    reinterpret_cast<LdrpReleaseTlsEntryFn>(fn_release_tls)(&fake_entry, nullptr);
#endif
                }
            }

            // 5. Free DLL memory and terminate thread
            // NtFreeVirtualMemory and RtlExitUserThread are in ntdll, fixed per boot session.
            auto* ntdll = GetModuleHandleA("ntdll.dll");
            auto* nt_free_vm = GetProcAddress(ntdll, "NtFreeVirtualMemory");
            auto* rtl_exit = GetProcAddress(ntdll, "RtlExitUserThread");

            if (!nt_free_vm || !rtl_exit)
                __fastfail(2);

            invoke_trampoline(base, nt_free_vm, rtl_exit);
        }
    } // namespace detail_unmap

    // Public API — call this from your injected DLL.
    // base: the HMODULE/hInstance received in DllMain(DLL_PROCESS_ATTACH).
    // This function never returns — it frees the DLL and terminates the thread.
    [[noreturn]] inline void self_unmap(void* base)
    {
        detail_unmap::self_unmap(base);
    }
} // namespace yail
