#include <yail/yail.hpp>
#include <yail/detail/process.hpp>
#include <Windows.h>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <string>

static constexpr int kNumCycles = 10;

static HANDLE OpenTargetProcess(const std::string& name)
{
    const auto pid = yail::detail::get_process_id_by_name(name);
    if (!pid)
        return nullptr;

    return OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD
                               | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
                               | PROCESS_VM_READ,
                       FALSE, static_cast<DWORD>(pid.value()));
}

static bool IsProcessAlive(HANDLE process)
{
    DWORD code = 0;
    GetExitCodeProcess(process, &code);
    return code == STILL_ACTIVE;
}

static void StressTLS(HANDLE process)
{
    for (int i = 0; i < 4; ++i)
    {
        HANDLE thread = CreateRemoteThread(process, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(Sleep),
                reinterpret_cast<LPVOID>(10), 0, nullptr);
        if (thread)
        {
            WaitForSingleObject(thread, 2000);
            CloseHandle(thread);
        }
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: test_cycle.exe <target.exe> [cycles=%d]\n", kNumCycles);
        fprintf(stderr, "  target.exe should be a long-running process (use test_host.exe).\n");
        return 1;
    }

    const std::string target_name(argv[1]);
    const int cycles = argc >= 3 ? std::atoi(argv[2]) : kNumCycles;
    constexpr const char* dll_path = "test_unload_dll.dll";

    printf("==============================================\n");
    printf("=== yail self_unmap cycle test              ===\n");
    printf("=== Target:   %-30s ===\n", target_name.c_str());
    printf("=== Payload:  %-30s ===\n", dll_path);
    printf("=== Cycles:   %-30d ===\n", cycles);
    printf("==============================================\n\n");
    fflush(stdout);

    int passed = 0;
    int failed = 0;

    for (int cycle = 1; cycle <= cycles; ++cycle)
    {
        printf("--- Cycle %d/%d ---\n", cycle, cycles);
        fflush(stdout);

        HANDLE process = OpenTargetProcess(target_name);
        if (!process)
        {
            fprintf(stderr, "  FAIL: cannot open '%s'\n", target_name.c_str());
            failed++;
            break;
        }

        if (!IsProcessAlive(process))
        {
            fprintf(stderr, "  FAIL: target process exited\n");
            CloseHandle(process);
            failed++;
            break;
        }

        const auto start = std::chrono::steady_clock::now();
        const auto result = yail::manual_map_injection_from_file(dll_path, target_name);
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();

        if (!result)
        {
            fprintf(stderr, "  FAIL: injection failed: %s\n", result.error().c_str());
            CloseHandle(process);
            failed++;
            continue;
        }

        printf("  Injected at 0x%llx (%lld ms)\n",
               static_cast<unsigned long long>(result.value()), elapsed);

        Sleep(150);

        if (!IsProcessAlive(process))
        {
            fprintf(stderr, "  FAIL: target crashed after self_unmap\n");
            CloseHandle(process);
            failed++;
            break;
        }

        StressTLS(process);
        Sleep(50);

        if (!IsProcessAlive(process))
        {
            fprintf(stderr, "  FAIL: target crashed after TLS stress\n");
            CloseHandle(process);
            failed++;
            break;
        }

        printf("  PASS\n");
        passed++;
        CloseHandle(process);
        Sleep(50);
    }

    printf("\n==============================================\n");
    printf("=== Results: %d/%d passed", passed, cycles);
    if (failed > 0) printf(", %d failed", failed);
    printf("               ===\n");
    printf("==============================================\n");

    return failed > 0 ? 1 : 0;
}
