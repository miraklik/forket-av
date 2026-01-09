#ifndef QUARANTINE_HPP
#define QUARANTINE_HPP

#include <string>
#include <vector>

class QuarantineManager {
public:
    QuarantineManager();

    bool quarantineFile(const std::string& filepath);

private:
    std::string quarantineDir; 
    const char XOR_KEY = 0x5A; 

    bool encryptAndMove(const std::string& src, const std::string& dst);
    
    void logQuarantine(const std::string& originalPath, const std::string& quarantinedName);
};

#endif