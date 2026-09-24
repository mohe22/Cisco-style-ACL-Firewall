// utils.hpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

enum class Action : uint8_t {
    Show,
    ShowAce,
    Add,
    Update,
    Delete,
    Unknown,
    Exit
};

std::vector<std::string> splitString(std::string_view text);

std::tuple<Action, std::vector<std::string>> getAction(std::string_view str) noexcept;

std::string actionToString(uint8_t action);
int stringToAction(const std::string& str);

std::string protocolToString(uint8_t protocol);
std::optional<uint8_t> protocolFromString(const std::string& str);

int toInt(const std::string& str);

std::string directionToString(uint8_t direction);
uint8_t stringToDirection(std::string_view direction);

std::string ipToString(uint32_t ip);
std::string ipToCiscoString(uint32_t ip);

std::string portToString(uint16_t port);
std::string portToCiscoString(uint16_t port);
