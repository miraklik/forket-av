#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <string>
#include <vector>

bool scanFile(const std::string& filepath);
bool scanDirParallel(const std::string& dirpath, int numThreads);
void updateSignatures(const std::string& signaturesFile);
void workerThread(int threadId);

extern std::vector<std::string> virusSignatures;

#endif