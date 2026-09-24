// logger.hpp
#pragma once

#include <fstream>
#include <mutex>
#include <string>

class Logger {
public:
    explicit Logger(const char* filename);

    void info(const std::string& message);
    void denied(const std::string& message);
    void error(const std::string& message);

private:
    std::ofstream file_;
    std::mutex mutex_;

    static std::string timestamp();
    void write(const char* prefix, const std::string& message);
};
