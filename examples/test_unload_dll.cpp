#include <Windows.h>
#include <DbgHelp.h>
#include <mmsystem.h>
#include <yail/unmap.hpp>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <stdexcept>
#include <memory>
#include <algorithm>

// =========================================================================
// Minimal self-test — runs a subset of tests, then calls self_unmap.
// No MessageBox, no user interaction.
// =========================================================================
static int g_passed = 0;
static int g_total  = 0;

static void Report(const char* name, bool ok)
{
    g_total++;
    if (ok) g_passed++;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

// TLS callback
static volatile bool g_tlsCallbackFired = false;

static void NTAPI TlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext)
{
    if (dwReason == DLL_PROCESS_ATTACH)
        g_tlsCallbackFired = true;
}

#ifdef _MSC_VER
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_pfnTlsCallback = TlsCallback;
#else
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK g_pfnTlsCallback = TlsCallback;
#endif

// Static TLS
static __declspec(thread) int g_tlsInt = 42;

static bool TestStaticTLS()
{
    if (g_tlsInt != 42) return false;
    g_tlsInt = 100;
    return g_tlsInt == 100;
}

// TLS per-thread
static bool TestTLSPerThread()
{
    std::atomic<bool> ok{false};
    g_tlsInt = 1000;
    std::thread t([&] {
        g_tlsInt = 111;
        ok = (g_tlsInt == 111);
    });
    t.join();
    return ok && g_tlsInt == 1000;
}

// SEH
static bool TestSEH()
{
    bool caught = false;
    __try { *reinterpret_cast<volatile int*>(nullptr) = 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { caught = true; }
    return caught;
}

// C++ exception
static bool TestCppException()
{
    try { throw std::runtime_error("test"); }
    catch (const std::exception& e) { return std::string(e.what()) == "test"; }
    return false;
}

// Imports
static bool TestImports()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return si.dwPageSize > 0;
}

// STL
static bool TestSTL()
{
    std::vector<int> v = {5, 3, 1, 4, 2};
    std::sort(v.begin(), v.end());
    return v == std::vector<int>{1, 2, 3, 4, 5};
}

// FPU
static bool TestFloatingPoint()
{
    volatile double a = 2.0;
    return fabs(sqrt(a) - 1.41421356237) < 1e-6;
}

// Threading
static bool TestThreading()
{
    std::atomic<int> counter{0};
    std::thread t1([&] { counter++; });
    std::thread t2([&] { counter++; });
    t1.join(); t2.join();
    return counter == 2;
}

// VTable
struct IAnimal { virtual const char* Speak() = 0; virtual ~IAnimal() = default; };
struct Dog : IAnimal { const char* Speak() override { return "Woof"; } };

static bool TestVTable()
{
    std::unique_ptr<IAnimal> d = std::make_unique<Dog>();
    return strcmp(d->Speak(), "Woof") == 0;
}

// Delay imports
static bool TestDelayImportDbgHelp()
{
    const DWORD original = SymGetOptions();
    SymSetOptions(original | SYMOPT_UNDNAME);
    const DWORD updated = SymGetOptions();
    SymSetOptions(original);
    return (updated & SYMOPT_UNDNAME) != 0;
}

static bool TestDelayImportWinmm()
{
    TIMECAPS tc{};
    return timeGetDevCaps(&tc, sizeof(tc)) == TIMERR_NOERROR
           && tc.wPeriodMin > 0 && tc.wPeriodMin <= tc.wPeriodMax;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    printf("[unload_dll] base=%p — running quick tests before self_unmap\n", hModule);

    Report("TLS callback",       g_tlsCallbackFired);
    Report("Static TLS",         TestStaticTLS());
    Report("TLS per-thread",     TestTLSPerThread());
    Report("SEH",                TestSEH());
    Report("C++ exception",      TestCppException());
    Report("Win32 imports",      TestImports());
    Report("STL",                TestSTL());
    Report("Floating point",     TestFloatingPoint());
    Report("Threading",          TestThreading());
    Report("VTable",             TestVTable());
    Report("Delay DbgHelp",      TestDelayImportDbgHelp());
    Report("Delay Winmm",        TestDelayImportWinmm());

    printf("[unload_dll] %d/%d passed — calling yail::self_unmap()\n", g_passed, g_total);
    fflush(stdout);

    yail::self_unmap(hModule);
}
