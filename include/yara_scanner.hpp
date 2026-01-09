#ifndef YARA_SCANNER_HPP
#define YARA_SCANNER_HPP

#include <string>
#include <yara.h>

class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();

    bool loadRules(const std::string& rulesPath);

    bool scanFile(const std::string& filepath);
private:
    YR_RULES* rules;
    YR_COMPILER* compiler;
    bool initialized;

    bool addFileToCompiler(const std::string& filepath);
    static int scanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);
};

#endif