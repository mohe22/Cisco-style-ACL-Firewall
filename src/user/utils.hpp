#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "../../include/common.h"

enum class Action : uint8_t {
    Show,
    ShowAce,
    Add,
    Update,
    Delete,
    Unknown,
    Exit
};

[[nodiscard]] std::vector<std::string> splitString(std::string_view text);
[[nodiscard]] std::tuple<Action, std::vector<std::string>> getAction(std::string_view str) noexcept;
[[nodiscard]] std::string actionToString(uint8_t action) noexcept;
[[nodiscard]] int stringToAction(std::string_view str) noexcept;
[[nodiscard]] std::string protocolToString(uint8_t protocol) noexcept;
[[nodiscard]] std::optional<uint8_t> protocolFromString(std::string_view str) noexcept;
[[nodiscard]] int toInt(std::string_view str) noexcept;
[[nodiscard]] std::string directionToString(uint8_t direction) noexcept;
[[nodiscard]] uint8_t stringToDirection(std::string_view direction) noexcept;
[[nodiscard]] std::string ipToString(uint32_t ip) noexcept;
[[nodiscard]] std::string ipToCiscoString(uint32_t ip) noexcept;
[[nodiscard]] std::string portToString(uint16_t port) noexcept;
[[nodiscard]] std::string portToCiscoString(uint16_t port) noexcept;
[[nodiscard]] std::string flagsToString(uint8_t flags) noexcept;
[[nodiscard]] std::string formatKtime(u64 ktimeNs) noexcept;
