// HWID Generator for Testing
// Compile: g++ -std=c++11 hwid-generator.cpp -o hwid_generator

#include <iostream>
#include <string>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <cstdio>
#include <cstring>
#endif

// Generate disk-based HWID
std::string generateDiskHWID() {
#ifdef _WIN32
    // Windows: Get volume serial number
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    std::string hwid = "disk_" + std::to_string(serial);
    
    // Add additional identifiers
    char computerName[256] = {0};
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        hwid += "_" + std::string(computerName);
    }
    
    return hwid;
#else
    // Linux/Mac: Use disk UUID or similar
    std::string hwid = "disk_unknown";
    FILE* pipe = popen("lsblk -o UUID -n | head -1", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            hwid = "disk_" + std::string(buffer);
            hwid.erase(std::remove(hwid.begin(), hwid.end(), '\n'), hwid.end());
        }
        pclose(pipe);
    }
    return hwid;
#endif
}

int main() {
    std::cout << "================================" << std::endl;
    std::cout << "  Disk-Based HWID Generator" << std::endl;
    std::cout << "================================" << std::endl;
    std::cout << std::endl;
    
    std::string hwid = generateDiskHWID();
    
    std::cout << "Your HWID: " << hwid << std::endl;
    std::cout << std::endl;
    
    std::cout << "This HWID is based on:" << std::endl;
#ifdef _WIN32
    std::cout << "- C: drive volume serial number" << std::endl;
    std::cout << "- Computer name" << std::endl;
#else
    std::cout << "- Disk UUID" << std::endl;
#endif
    std::cout << std::endl;
    
    std::cout << "Use this HWID to test key locking." << std::endl;
    
    return 0;
}
