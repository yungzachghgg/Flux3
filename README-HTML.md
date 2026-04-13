# HTML-Only API Key Manager

Pure HTML/CSS/JS solution - no server needed! Works entirely in the browser with a free cloud backend.

## How It Works

- **Frontend**: Single HTML file with embedded CSS and JavaScript
- **Backend**: Uses jsonbin.io (free cloud JSON storage)
- **Auth**: SHA-256 password hashing, JWT-like session stored in localStorage
- **API Keys**: Generated client-side, stored in shared cloud database

## Quick Start

### Option 1: Just Open The File (Local Testing)
1. Double-click `auth.html` to open in browser
2. It will work with demo data (stored temporarily)

### Option 2: Deploy for Real Use

#### Step 1: Get a Free jsonbin.io Account
1. Go to https://jsonbin.io
2. Sign up (free)
3. Click "API Keys" in the menu
4. Copy your **Master Key** (starts with `$2a$10$`)

#### Step 2: Create a Bin
1. Click "New Bin"
2. Paste this JSON content:
   ```json
   {
     "users": {}
   }
   ```
3. Click "Create"
4. Copy the Bin ID from the URL (e.g., `67f73c1e8a456b79668ac36e`)

#### Step 3: Update auth.html
Open `auth.html` in a text editor and replace these lines at the top:

```javascript
const MASTER_KEY = '$2a$10$YourJsonBinMasterKeyHere';  // Replace with your key
// And in getUsersBin()/saveUsersBin(), update the bin ID in the URL
// Change: 67f73c1e8a456b79668ac36e to YOUR bin ID
```

#### Step 4: Deploy Anywhere
Upload `auth.html` to any static host:
- **GitHub Pages** (free)
- **Netlify** (drag & drop)
- **Vercel** (drag & drop)
- **Any web server** (Apache, Nginx, etc.)

## For Your C++ App

Use the API keys generated in the web UI. Example HTTP request:

```cpp
#include <iostream>
#include <string>
#include <curl/curl.h>

// Callback for libcurl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string apiRequest(const std::string& url, const std::string& apiKey) {
    CURL* curl = curl_easy_init();
    std::string response;
    
    if (curl) {
        struct curl_slist* headers = NULL;
        std::string authHeader = "X-API-Key: " + apiKey;
        headers = curl_slist_append(headers, authHeader.c_str());
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        CURLcode res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            response = std::string("Error: ") + curl_easy_strerror(res);
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    
    return response;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <api_key>" << std::endl;
        return 1;
    }
    
    std::string apiKey = argv[1];
    
    // Example: Call your API
    std::string result = apiRequest("https://your-api.com/data", apiKey);
    std::cout << result << std::endl;
    
    return 0;
}
```

Compile: `g++ -std=c++11 cpp_client.cpp -o client -lcurl`

## Security Notes

⚠️ **This is a simplified solution suitable for:**
- Personal projects
- Low-risk applications
- Learning/development

⚠️ **Not suitable for:**
- High-security production apps
- Financial/medical data
- Apps with sensitive user information

For production use, consider:
- Firebase Auth (free tier available)
- Supabase (free tier available)
- Self-hosted Node.js with proper database

## Features

- ✅ User registration/login
- ✅ API key generation
- ✅ View all keys
- ✅ Revoke keys
- ✅ Copy to clipboard
- ✅ Works on any device
- ✅ No installation required
- ✅ Mobile-friendly design

## Free Limits (jsonbin.io)

- 10,000 requests/month (free plan)
- 100 KB per bin
- Perfect for small-medium projects
