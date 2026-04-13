# Auth API Service

Self-hosted authentication service with API key generation for C++ clients.

## Quick Start

```bash
# Install dependencies
npm install

# Start server
npm start

# Or with auto-reload for development
npm run dev
```

Server runs on `http://localhost:3000`

## Features

- **User Registration/Login** - JWT-based authentication
- **API Key Management** - Generate, view, and revoke keys via web UI
- **API Key Auth** - C++ clients authenticate using `X-API-Key` header
- **SQLite Database** - Zero-config, file-based storage

## Web Interface

Open `http://localhost:3000` in your browser to:
- Register/login to your account
- Generate API keys for your C++ apps
- View and revoke existing keys

## API Endpoints

### Auth (Web UI)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Create account |
| POST | `/api/auth/login` | Get JWT token |
| POST | `/api/keys/generate` | Create API key (requires JWT) |
| GET | `/api/keys` | List your keys (requires JWT) |
| DELETE | `/api/keys/:id` | Revoke key (requires JWT) |

### Protected (C++ Clients)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check (no auth) |
| GET | `/api/data` | Example protected route (requires `X-API-Key` header) |

## C++ Integration

### 1. Get an API Key
1. Register at `http://localhost:3000`
2. Click "Generate API Key"
3. Copy the key (starts with `ak_`)

### 2. Use in C++

```cpp
// Add header to your HTTP requests:
// X-API-Key: your_api_key_here

// Example with libcurl:
curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:3000/api/data");
struct curl_slist* headers = NULL;
headers = curl_slist_append(headers, "X-API-Key: ak_your_key_here");
curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
```

### 3. Compile Example

```bash
# Linux/Mac (install libcurl first)
g++ -std=c++11 cpp_example.cpp -o cpp_client -lcurl

# Windows (with vcpkg)
g++ -std=c++11 cpp_example.cpp -o cpp_client -lcurl
```

Run it:
```bash
./cpp_client ak_your_api_key_here
```

## Database

SQLite database stored in `auth.db`. Tables:
- `users` - accounts
- `api_keys` - generated keys with usage tracking

## Production Notes

1. **Change JWT_SECRET** - Set environment variable:
   ```bash
   set JWT_SECRET=your-random-secret-here
   ```

2. **HTTPS** - Use a reverse proxy (nginx/caddy) for TLS

3. **Database** - Consider migrating to PostgreSQL for high load

## File Structure

```
.
├── server.js          # Main Express server
├── public/
│   └── index.html     # Web UI
├── cpp_example.cpp    # C++ client example
├── package.json
└── README.md
```
