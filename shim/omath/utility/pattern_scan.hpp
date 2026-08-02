#pragma once
#include <algorithm>
#include <cstddef>
#include <string_view>
#include <vector>

namespace omath
{
    class PatternScanner final
    {
    public:
        PatternScanner() = delete;

        [[nodiscard]]
        static std::byte* scan_for_pattern(std::byte* begin, std::byte* end, std::string_view signature)
        {
            const auto [pattern, mask] = parse_signature(signature);
            if (pattern.empty())
                return end;

            const auto result = std::search(
                begin, end,
                pattern.begin(), pattern.end(),
                [&](std::byte b, std::byte p) {
                    return p == static_cast<std::byte>(0) || b == p;
                });

            return result;
        }

    private:
        [[nodiscard]]
        static std::pair<std::vector<std::byte>, std::vector<std::byte>> parse_signature(std::string_view signature)
        {
            std::vector<std::byte> pattern;
            std::vector<std::byte> mask;

            for (std::size_t i = 0; i < signature.size(); ++i)
            {
                if (signature[i] == ' ')
                    continue;

                if (signature[i] == '?' || (i + 1 < signature.size() && signature[i + 1] == '?'))
                {
                    pattern.push_back(static_cast<std::byte>(0));
                    mask.push_back(static_cast<std::byte>(0xFF));
                    if (signature[i] == '?')
                        ++i;
                    else
                        i += 2;
                    continue;
                }

                if (i + 1 >= signature.size())
                    break;

                char high = signature[i];
                char low = signature[i + 1];
                ++i;

                auto hex_to_nibble = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    return 0;
                };

                const std::uint8_t byte = static_cast<std::uint8_t>(
                    (hex_to_nibble(high) << 4) | hex_to_nibble(low));
                pattern.push_back(static_cast<std::byte>(byte));
                mask.push_back(static_cast<std::byte>(0));
            }

            for (std::size_t j = 0; j < mask.size(); ++j)
            {
                if (mask[j] == static_cast<std::byte>(0xFF))
                    pattern[j] = static_cast<std::byte>(0);
            }

            return {std::move(pattern), std::move(mask)};
        }
    };
}
