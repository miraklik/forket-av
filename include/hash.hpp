#ifndef HASH_HPP
#define HASH_HPP

#include <string>

std::string calculateSHA256(const std::string& filepath);

bool checkDatabase(const std::string& fileHash);

void loadHashDatabase(const std::string& databaseFile);

#endif