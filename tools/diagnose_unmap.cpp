#include <Windows.h>
#include <cstdio>
#include <cstdint>

int main()
{
    auto* ntdll = GetModuleHandleA("ntdll.dll");
    printf("Loaded ntdll base: %p\n", ntdll);

    // Read the PE header to get the checksum/timestamp for comparison
    auto* dos = (const IMAGE_DOS_HEADER*)ntdll;
    auto* nt = (const IMAGE_NT_HEADERS*)((const uint8_t*)ntdll + dos->e_lfanew);
    printf("TimeDateStamp: 0x%08X\n", nt->FileHeader.TimeDateStamp);
    printf("SizeOfImage:   0x%08X (%u)\n\n", nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.SizeOfImage);

    // Scan for functions matching the user's partial pattern (just the first few bytes)
    // "48 89 5C 24 ? 57" — mov [rsp+X], rbx; push rdi
    const uint8_t* base = (const uint8_t*)ntdll;
    const uint8_t* end = base + nt->OptionalHeader.SizeOfImage;
    int count = 0;
    printf("Functions matching '48 89 5C 24 ?? 57' followed by '48 8B FA 48 8B D9 48 85 D2':\n\n");
    for (const uint8_t* cur = base; cur < end - 20; ++cur)
    {
        if (cur[0] != 0x48 || cur[1] != 0x89 || cur[2] != 0x5C || cur[3] != 0x24) continue;
        if (cur[4] != 0x57) continue;
        // Check for mov rdi, rdx; mov rbx, rcx; test rdx, rdx within next 20 bytes
        for (int off = 5; off < 20; ++off)
        {
            if (cur[off] == 0x48 && cur[off+1] == 0x8B && cur[off+2] == 0xFA &&
                cur[off+3] == 0x48 && cur[off+4] == 0x8B && cur[off+5] == 0xD9 &&
                cur[off+6] == 0x48 && cur[off+7] == 0x85 && cur[off+8] == 0xD2)
            {
                printf("  Match at %p (offset 0x%llx): ", cur, (unsigned long long)(cur - base));
                for (int i = 0; i < 30; ++i) printf("%02X ", cur[i]);
                printf("\n");
                count++;
                break;
            }
        }
    }
    printf("Total: %d matches\n", count);

    return 0;
}
