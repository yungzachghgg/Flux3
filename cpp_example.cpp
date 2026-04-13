// Example C++ client for the auth API
// Compile with: g++ -std=c++11 cpp_example.cpp -o cpp_client -lcurl

#include <iostream>
#include <string>
#include <curl/curl.h>

// Callback for libcurl to write response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Make HTTP GET request with API key
std::string apiGet(const std::string& url, const std::string& apiKey) {
    CURL* curl = curl_easy_init();
    std::string response;
    
    if (curl) {
        struct curl_slist* headers = NULL;
        std::string authHeader = "X-API-Key: " + apiKey;
        headers = curl_slist_append(headers, authHeader.c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        CURLcode res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            response = "Error: " + std::string(curl_easy_strerror(res));
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    
    return response;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <api_key>" << std::endl;
        std::cout << "Example: " << argv[0] << " ak_550e8400e29b41d4a716446655440000" << std::endl;
        std::cout << "\nGet your API key from the web interface at http://localhost:3000" << std::endl;
        return 1;
    }
    
    std::string apiKey = argv[1];
    std::string baseUrl = "http://localhost:3000";
    
    std::cout << "Testing API key: " << apiKey << std::endl;
    std::cout << "Server: " << baseUrl << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    
    // Test health endpoint (no auth required)
    std::cout << "\n1. Health Check (no auth):" << std::endl;
    CURL* curl = curl_easy_init();
    std::string healthResponse;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, (baseUrl + "/api/health").c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &healthResponse);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    std::cout << healthResponse << std::endl;
    
    // Test protected endpoint with API key
    std::cout << "\n2. Protected Endpoint (with API key):" << std::endl;
    std::string dataResponse = apiGet(baseUrl + "/api/data", apiKey);
    std::cout << dataResponse << std::endl;
    
    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "Done!" << std::endl;
    
    return 0;
}
