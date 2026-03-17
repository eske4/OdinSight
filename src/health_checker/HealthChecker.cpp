#include "HealthChecker.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <optional>

namespace fs = std::filesystem;

namespace HealthChecker
{
    std::optional<std::string> findSecureBootFile()
    {
        const std::string path = "/sys/firmware/efi/efivars/"; // look into std::string_view, make file system path object

        for (const auto &entry : fs::directory_iterator(path))
        {
            const auto &filename = entry.path().filename().string();

            if (filename.rfind("SecureBoot-", 0) == 0)
            {
                return entry.path().string();
            }
        }

        return std::nullopt;
    }

    bool isSecureBootEnabled()
    {
        std::optional<std::string> secureBootFilePath = findSecureBootFile();

        if (!secureBootFilePath)
        {
            return false;
        }

        std::ifstream secureBootFile(*secureBootFilePath, std::ios::binary);

        if (!secureBootFile.is_open())
        {
            return false;
        }

        char byte;
        uint8_t lastByte = 0;

        while (secureBootFile.get(byte))
        {
            lastByte = static_cast<unsigned char>(byte); // Update lastByte with each byte
        }

        // std::cout << "Last byte: " << static_cast<int>(lastByte) << std::endl; // For debugging

        return lastByte == 1;
    }

    HealthStatus performHealthCheck()
    {
        HealthStatus status;
        status.secureBootEnabled = isSecureBootEnabled();
        return status;
    }

    void printHealthStatus()
    {
        HealthStatus status = performHealthCheck();

        std::cout << "Secure Boot Enabled: " << (status.secureBootEnabled) << std::endl;
    }
}