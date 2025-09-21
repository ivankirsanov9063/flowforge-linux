#include "Server.hpp"

#include <vector>
#include <chrono>
#include <thread>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <fstream>

bool working = true;

void OnExit(int)
{
    Stop();
    working = false;
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << (argc > 0 ? argv[0] : "app") << " <config.json>\n";
        return 1;
    }

    const std::string path = argv[1];

    std::ifstream in(path, std::ios::binary);
    if (!in.is_open())
    {
        std::cerr << "Error: cannot open file: " << path << "\n";
        return 1;
    }

    std::string config;

    // Опционально резервируем размер (если доступен и вмещается в size_t).
    {
        std::error_code ec;
        const auto fsz = std::filesystem::file_size(path, ec);
        if (!ec && fsz <= static_cast<uintmax_t>(std::numeric_limits<size_t>::max()))
        {
            config.reserve(static_cast<size_t>(fsz));
        }
    }

    // Читаем весь файл в строку.
    config.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());

    if (in.bad())
    {
        std::cerr << "Error: I/O error while reading file: " << path << "\n";
        return 1;
    }

    // Удаляем BOM, если есть.
    if (config.size() >= 3 &&
        static_cast<unsigned char>(config[0]) == 0xEF &&
        static_cast<unsigned char>(config[1]) == 0xBB &&
        static_cast<unsigned char>(config[2]) == 0xBF)
    {
        config.erase(0, 3);
    }

    Start(config.data());
    std::signal(SIGINT,  OnExit);
    std::signal(SIGTERM, OnExit);

    while (working)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}
