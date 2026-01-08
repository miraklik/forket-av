#include "hash.hpp"
#include <openssl/sha.h>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <stdio.h>

std::unordered_set<std::string> maliciousHashes;

std::string calculateSHA256(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);

    if (!file.is_open()) {
        printf("Failed to open file: %s\n", filepath.c_str());
        return;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    const size_t buffer_size = 32768;
    char buffer[buffer_size];

    while (file.read(buffer, buffer_size)) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    if (file.gcount() > 0) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

void loadHashDatabase(const std::string& databaseFile) {
    std::ifstream file(databaseFile);

    if(!file.is_open()) {
        printf("Failed to open hash database file: %s\n", databaseFile.c_str());
        return;
    }

    maliciousHashes.clear();

    std::string line;
    int count = 0;

    while (std::getline(file, line)) {
        line.erase(line.find_last_not_of(" \n\r\t") + 1);

        if (!line.empty()) {
            maliciousHashes.insert(line);
            count++;
        }
    }

    printf("Loaded %d malicious hashes from %s\n", count, databaseFile.c_str());
}

bool checkDatabase(const std::string& fileHash) {
    return maliciousHashes.find(fileHash) != maliciousHashes.end();
}