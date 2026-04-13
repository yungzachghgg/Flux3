// KeyAuth-style C++ Example
// Compile: g++ -std=c++11 cpp-keyauth-example.cpp -o keyauth_client -lcurl

#include <iostream>
#include <string>
#include <curl/curl.h>
#include <json/json.h> // Install: apt-get install libjsoncpp-dev (or vcpkg install jsoncpp)

// Callback for libcurl to write response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Parse simple JSON (without external lib, you can use this simple parser)
bool parseJsonResponse(const std::string& json, std::string& success, std::string& message, std::string& subscription) {
    // Simple parsing - look for "success":true/false
    size_t pos = json.find("\"success\":");
    if (pos == std::string::npos) return false;
    
    pos += 10; // skip "\success\":"
    success = json.substr(pos, 4);
    if (success.find("true") != std::string::npos) success = "true";
    else success = "false";
    
    // Look for message
    pos = json.find("\"message\":\"");
    if (pos != std::string::npos) {
        pos += 11;
        size_t end = json.find("\"", pos);
        message = json.substr(pos, end - pos);
    }
    
    // Look for subscription
    pos = json.find("\"subscription\":\"");
    if (pos != std::string::npos) {
        pos += 15;
        size_t end = json.find("\"", pos);
        subscription = json.substr(pos, end - pos);
    }
    
    return true;
}

class KeyAuthAPI {
private:
    std::string apiUrl;
    std::string currentKey;
    std::string hwid;
    bool authenticated;
    
public:
    KeyAuthAPI(const std::string& url) : apiUrl(url), authenticated(false) {
        // Generate simple HWID (in production, use machine-specific info)
        hwid = "hwid_" + std::to_string(time(nullptr));
    }
    
    bool validateKey(const std::string& key) {
        CURL* curl = curl_easy_init();
        std::string response;
        
        if (!curl) return false;
        
        // Build POST data
        std::string postData = "key=" + key + "&hwid=" + hwid;
        
        curl_easy_setopt(curl, CURLOPT_URL, (apiUrl + "/api/auth/validate").c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        // Set headers
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        CURLcode res = curl_easy_perform(curl);
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK) {
            std::cerr << "Request failed: " << curl_easy_strerror(res) << std::endl;
            return false;
        }
        
        // Parse response
        std::string success, message, subscription;
        if (parseJsonResponse(response, success, message, subscription)) {
            if (success == "true") {
                currentKey = key;
                authenticated = true;
                std::cout << "✓ " << message << std::endl;
                std::cout << "  Subscription: " << subscription << std::endl;
                return true;
            } else {
                std::cerr << "✗ " << message << std::endl;
                return false;
            }
        }
        
        std::cerr << "Failed to parse response" << std::endl;
        return false;
    }
    
    bool isAuthenticated() const {
        return authenticated;
    }
    
    std::string getKey() const {
        return currentKey;
    }
};

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " <api_key> [api_url]" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << prog << " ak_xxxxxxxxxxxxxxx" << std::endl;
    std::cout << "  " << prog << " ak_xxxxxxxxxxxxxxx http://localhost:3000" << std::endl;
    std::cout << std::endl;
    std::cout << "Get your API key from the web dashboard" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string apiKey = argv[1];
    std::string apiUrl = (argc > 2) ? argv[2] : "http://localhost:3000";
    
    std::cout << "================================" << std::endl;
    std::cout << "  KeyAuth-Style Client" << std::endl;
    std::cout << "================================" << std::endl;
    std::cout << std::endl;
    std::cout << "API URL: " << apiUrl << std::endl;
    std::cout << "Key: " << apiKey << std::endl;
    std::cout << std::endl;
    
    // Create API client
    KeyAuthAPI auth(apiUrl);
    
    // Validate key
    std::cout << "Validating key..." << std::endl;
    
    if (auth.validateKey(apiKey)) {
        std::cout << std::endl;
        std::cout << "╔══════════════════════════════╗" << std::endl;
        std::cout << "║    AUTHENTICATION SUCCESS    ║" << std::endl;
        std::cout << "╚══════════════════════════════╝" << std::endl;
        std::cout << std::endl;
        
        // Your protected code here
        std::cout << "Running protected application..." << std::endl;
        
        // Example: Periodic re-validation
        for (int i = 0; i < 3; i++) {
            std::cout << "  [Session " << (i+1) << "] Still authenticated" << std::endl;
            // In real app, you might re-validate periodically
        }
        
        std::cout << std::endl;
        std::cout << "Application complete." << std::endl;
        
        return 0;
    } else {
        std::cout << std::endl;
        std::cout << "╔══════════════════════════════╗" << std::endl;
        std::cout << "║    AUTHENTICATION FAILED     ║" << std::endl;
        std::cout << "╚══════════════════════════════╝" << std::endl;
        std::cout << std::endl;
        std::cout << "Exiting..." << std::endl;
        
        return 1;
    }
}
