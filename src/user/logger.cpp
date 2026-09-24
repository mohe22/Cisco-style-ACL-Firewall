// logger.cpp
#include "logger.hpp"

#include <ctime>
#include <stdexcept>

Logger::Logger(const char* filename) : file_(filename, std::ios::app) {
    if (!file_)
        throw std::runtime_error("Failed to open log file");
}

void Logger::info(const std::string& message) {
    write("%ACL-5-INFO: ", message);
}

void Logger::denied(const std::string& message) {
    write("%ACL-4-DENIED: ", message);
}

void Logger::error(const std::string& message) {
    write("%ACL-3-ERROR: ", message);
}

std::string Logger::timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&now, &tmv);

    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmv);

    return buffer;
}

void Logger::write(const char* prefix, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    file_ << timestamp() << ' ' << prefix << message << '\n';
    file_.flush();
}
