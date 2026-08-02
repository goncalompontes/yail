#include <Windows.h>
#include <cstdio>
#include <atomic>
#include <thread>
#include <chrono>

static std::atomic<bool> g_running{true};

static void WorkerThread()
{
    // Each thread exercises TLS allocation in the OS.
    // If a previously unmapped DLL left stale TLS entries,
    // these thread creations will trigger heap corruption.
    volatile int x = 42;
    (void)x;
    Sleep(50);
}

static DWORD WINAPI ThreadProc(LPVOID)
{
    WorkerThread();
    return 0;
}

int main()
{
    printf("[test_host] PID=%lu — running, press Ctrl+C to stop\n", GetCurrentProcessId());
    printf("[test_host] Periodically creating/destroying threads to stress TLS\n");

    while (g_running)
    {
        constexpr int kNumThreads = 4;
        HANDLE threads[kNumThreads]{};

        for (int i = 0; i < kNumThreads; ++i)
        {
            threads[i] = CreateThread(nullptr, 0, ThreadProc, nullptr, 0, nullptr);
            if (!threads[i])
            {
                printf("[test_host] ERROR: CreateThread failed (%lu)\n", GetLastError());
                return 1;
            }
        }

        WaitForMultipleObjects(kNumThreads, threads, TRUE, INFINITE);

        for (auto h : threads)
            CloseHandle(h);

        Sleep(200);
    }

    return 0;
}
