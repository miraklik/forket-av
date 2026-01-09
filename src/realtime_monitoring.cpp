#include "realtime_monitoring.hpp"
#include <CoreServices/CoreServices.h>
#include <stdio.h>

struct CallbackData {
    FileEventCallback userCallback;
};

void fseventsCallback(
    ConstFSEventStreamRef streamRef,
    void *clientCallbackInfo,
    size_t numEvents,
    void *eventPaths,
    const FSEventStreamEventFlags eventFlags[],
    const FSEventStreamEventId eventIds[])
{
    CallbackData* data = static_cast<CallbackData*>(clientCallbackInfo);
    char **paths = static_cast<char**>(eventPaths);
    
    for (size_t i = 0; i < numEvents; i++) { 
        std::string path(paths[i]);
        FSEventStreamEventFlags flags = eventFlags[i];

        bool isCreated = flags & kFSEventStreamEventFlagItemCreated;
        bool isModified = flags & kFSEventStreamEventFlagItemModified;
        bool isRemoved = flags & kFSEventStreamEventFlagItemRemoved;

        if (isRemoved) {
            continue;
        }

        if (data->userCallback && (isCreated || isModified)) {
            data->userCallback(path, isCreated, isModified);
        }
    }
}

RealTimeMonitoring::RealTimeMonitoring() : eventStream(nullptr), running(false) {}

RealTimeMonitoring::~RealTimeMonitoring() {
    stopMonitoring();
}

bool RealTimeMonitoring::startMonitoring(const std::string& path, FileEventCallback callback) {
    if (running) {
        printf("Real-time monitoring is already running\n");
        return false;
    }

    CallbackData* data = new CallbackData();
    data->userCallback = callback;

    CFStringRef pathRef = CFStringCreateWithCString(
        kCFAllocatorDefault,
        path.c_str(),
        kCFStringEncodingUTF8
    );

    CFArrayRef pathsToWatch = CFArrayCreate(
        kCFAllocatorDefault,
        (const void**)&pathRef,
        1,
        &kCFTypeArrayCallBacks
    );
    
    CFAbsoluteTime latency = 1.0;

    FSEventStreamContext context = {0, data, NULL, NULL, NULL};
    
    FSEventStreamRef stream = FSEventStreamCreate(
        kCFAllocatorDefault,
        &fseventsCallback,
        &context,
        pathsToWatch,
        kFSEventStreamEventIdSinceNow,
        latency,
        kFSEventStreamCreateFlagFileEvents
    );
    
    if (!stream) {
        printf("Failed to create FSEventStream\n");
        CFRelease(pathsToWatch);
        CFRelease(pathRef);
        delete data;
        return false;
    }
    
    eventStream = stream;
    
    FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    
    if (!FSEventStreamStart(stream)) {
        printf("Failed to start FSEventStream\n");
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        CFRelease(pathsToWatch);
        CFRelease(pathRef);
        delete data;
        eventStream = nullptr;
        return false;
    }
    
    running = true;
    
    printf("Real-time monitoring started for: %s\n", path.c_str());
    
    CFRelease(pathsToWatch);
    CFRelease(pathRef);
    
    return true;
}

void RealTimeMonitoring::stopMonitoring() {
    if (!running || !eventStream) {
        return;
    }

    FSEventStreamRef stream = static_cast<FSEventStreamRef>(eventStream);
    
    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
    
    eventStream = nullptr;
    running = false;
    
    printf("Real-time monitoring stopped\n");
}

bool RealTimeMonitoring::isRunning() const {
    return running;
}