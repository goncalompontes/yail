#pragma once
#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <omath/utility/pattern_scan.hpp>
#include <optional>
#include <string_view>

namespace omath
{
    class PePatternScanner final
    {
    public:
        PePatternScanner() = delete;

        [[nodiscard]]
        static std::optional<std::uintptr_t> scan_for_pattern_in_loaded_module(
            const void* module, std::string_view signature)
        {
            auto* dos = static_cast<IMAGE_DOS_HEADER*>(const_cast<void*>(module));
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return std::nullopt;

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                static_cast<std::uint8_t*>(const_cast<void*>(module)) + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return std::nullopt;

            auto* begin = static_cast<std::byte*>(const_cast<void*>(module));
            auto* end = begin + nt->OptionalHeader.SizeOfImage;

            auto* result = PatternScanner::scan_for_pattern(begin, end, signature);
            if (result == end)
                return std::nullopt;

            return reinterpret_cast<std::uintptr_t>(result);
        }
    };
}
