#ifndef REALTIME_MONITORING_HPP
#define REALTIME_MONITORING_HPP

#include <string>
#include <functional>

using FileEventCallback = std::function<void(const std::string& path, bool isCreated, bool isModified)>;

class RealTimeMonitoring {
public:
    RealTimeMonitoring();
    ~RealTimeMonitoring();
    
    bool startMonitoring(const std::string& path, FileEventCallback callback);
    void stopMonitoring();
    bool isRunning() const;

private:
    void* eventStream;
    bool running;
};

#endif 