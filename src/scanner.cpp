#include "scanner.hpp"
#include <stdio.h>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <iostream>

std::vector<std::string> virusSignatures = {"\x45\x69\x63\x61\x72"};

bool scanFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if(!file.is_open()) {
        std::printf("Failed to open file: %s\n", filepath.c_str());
        return false;
    }
    
    std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    for(const auto& signature: virusSignatures) {
        size_t pos = file_content.find(signature);
        if (pos != std::string::npos) {
            std::printf("Virus found in %s\n", filepath.c_str());
            return true;
        }
    }

    std::printf("Virus not found in %s\n", filepath.c_str());
    return false;
}

bool scanDir(const std::string& dirpath) {
    bool virusFound = false;

    try {
        if (!std::filesystem::exists(dirpath)) {
            std::printf("Directory %s does not exist\n", dirpath.c_str());
            return false;
        }

        if (!std::filesystem::is_directory(dirpath)) {
            std::printf("%s is not a directory\n", dirpath.c_str());
            return false;
        }

        std::printf("Scanning directory %s\n", dirpath.c_str());

        for(const auto& entry: std::filesystem::recursive_directory_iterator(dirpath)) {
            if (entry.is_regular_file()) {
                std::printf("Scanning: %s\n", entry.path().string().c_str());
                
                if (scanFile(entry.path().string())) {
                    virusFound = true;
                }
            }
        }

        if (virusFound) {
            std::printf("\n[!] Viruses detected in directory!\n");
        } else {
            std::printf("\n[+] Directory is clean\n");
        }
    }
    catch(const std::filesystem::filesystem_error& e) {
        std::printf("Filesystem error: %s\n", e.what());
        return false;
    }
    catch(const std::exception& e) {
        std::printf("Error: %s\n", e.what());
        return false;
    }
    
    return virusFound;
}

void updateSignatures(const std::string& signaturesFile) {
    std::ifstream file(signaturesFile);

    if(!file.is_open()) {
        std::printf("Failed to open signatures file: %s\n", signaturesFile.c_str());
        return;
    }

    virusSignatures.clear();

    std::string line;
    int count = 0;

    while (std::getline(file, line)) {
        if (!line.empty()) {
            virusSignatures.push_back(line);
            count++;
        }
    }

    std::printf("Loaded %d virus signatures from %s\n", count, signaturesFile.c_str());
}