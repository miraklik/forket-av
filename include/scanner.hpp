#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <string>
#include <vector>

bool scanFile(const std::string& filepath);
bool scanDir(const std::string& dirpath);
void updateSignatures(const std::string& signaturesFile);

extern std::vector<std::string> virusSignatures;

#endif