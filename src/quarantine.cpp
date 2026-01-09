#include "quarantine.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <ctime>   

namespace fs = std::filesystem;

QuarantineManager::QuarantineManager() {
    const char* homeDir = std::getenv("HOME");
    if (!homeDir) homeDir = std::getenv("USERPROFILE");

    if (homeDir) {
        quarantineDir = std::string(homeDir) + "/.forket_quarantine";
        
        if (!fs::exists(quarantineDir)) {
            fs::create_directory(quarantineDir);
            fs::permissions(quarantineDir, fs::perms::owner_all, fs::perm_options::replace);
        }
    } else {
        quarantineDir = "quarantine";
        fs::create_directory(quarantineDir);
    }
}

bool QuarantineManager::quarantineFile(const std::string& filepath) {
    if (!fs::exists(filepath)) return false;

    std::string filename = fs::path(filepath).filename().string();
    std::string destPath = quarantineDir + "/" + filename + ".vir";

    printf("[QUARANTINE] Moving file to: %s", destPath);

    if (encryptAndMove(filepath, destPath)) {
        try {
            fs::remove(filepath);
            printf("SUCCESS");
            logQuarantine(filepath, filename + ".vir");
            return true;
        } catch (const fs::filesystem_error& e) {
            printf("FAILED to delete original (Permission denied?)");
            return false;
        }
    } else {
        printf("FAILED to encrypt");
        return false;
    }
}

bool QuarantineManager::encryptAndMove(const std::string& src, const std::string& dst) {
    std::ifstream input(src, std::ios::binary);
    std::ofstream output(dst, std::ios::binary);

    if (!input.is_open() || !output.is_open()) return false;

    char buffer[4096]; 
    while (input.read(buffer, sizeof(buffer))) {
        std::streamsize bytesRead = input.gcount();
        for (int i = 0; i < bytesRead; ++i) {
            buffer[i] ^= XOR_KEY;
        }
        output.write(buffer, bytesRead);
    }

    if (input.gcount() > 0) {
         std::streamsize bytesRead = input.gcount();
         for (int i = 0; i < bytesRead; ++i) buffer[i] ^= XOR_KEY;
         output.write(buffer, bytesRead);
    }

    return true;
}

void QuarantineManager::logQuarantine(const std::string& originalPath, const std::string& quarantinedName) {
    std::ofstream logFile(quarantineDir + "/quarantine_log.txt", std::ios::app);
    if (logFile.is_open()) {
        std::time_t t = std::time(nullptr);
        char timeStr[100];
        std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        
        logFile << "[" << timeStr << "] Quarantined: " << originalPath 
                << " -> " << quarantinedName << "\n";
    }
}