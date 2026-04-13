# KeyAuth Server Starter
# Double-click this file or right-click -> Run with PowerShell

$Host.UI.RawUI.WindowTitle = "KeyAuth Server"

Write-Host "================================" -ForegroundColor Cyan
Write-Host "  KeyAuth Server Starter" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check if Node.js is installed
try {
    $nodeVersion = node --version 2>$null
    if (-not $nodeVersion) {
        Write-Host "ERROR: Node.js is not installed!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Download and install Node.js from:" -ForegroundColor Yellow
        Write-Host "https://nodejs.org" -ForegroundColor Blue
        Write-Host ""
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    Write-Host "✓ Node.js found: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Node.js is not installed!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Download and install Node.js from:" -ForegroundColor Yellow
    Write-Host "https://nodejs.org" -ForegroundColor Blue
    Write-Host ""
    pause
    exit 1
}

# Check if dependencies are installed
if (-not (Test-Path "node_modules")) {
    Write-Host ""
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install dependencies" -ForegroundColor Red
        pause
        exit 1
    }
    Write-Host "✓ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "✓ Dependencies already installed" -ForegroundColor Green
}

Write-Host ""
Write-Host "Starting KeyAuth Server..." -ForegroundColor Cyan
Write-Host ""

# Start the server in background
$serverJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    node keyauth-server.js 2>&1
}

# Wait for server to start
Write-Host "Waiting for server to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

# Check if server is running
$serverOutput = Receive-Job $serverJob -Keep
if ($serverOutput -match "error" -or $serverOutput -match "Error") {
    Write-Host "ERROR: Server failed to start" -ForegroundColor Red
    Write-Host $serverOutput
    Stop-Job $serverJob
    Remove-Job $serverJob
    pause
    exit 1
}

Write-Host "✓ Server is running!" -ForegroundColor Green
Write-Host ""
Write-Host "Dashboard URL: " -NoNewline
Write-Host "http://localhost:3000/keyauth.html" -ForegroundColor Blue -BackgroundColor Black
Write-Host "API Endpoint:    " -NoNewline
Write-Host "http://localhost:3000/api/auth/validate" -ForegroundColor Blue -BackgroundColor Black
Write-Host ""
Write-Host "Opening browser..." -ForegroundColor Yellow

# Open browser
Start-Process "http://localhost:3000/keyauth.html"

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Server is running!" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Show server output
while ($true) {
    $output = Receive-Job $serverJob
    if ($output) {
        foreach ($line in $output) {
            # Color-code different types of log messages
            if ($line -match "error|Error|ERROR") {
                Write-Host $line -ForegroundColor Red
            } elseif ($line -match "GET|POST") {
                Write-Host $line -ForegroundColor Cyan
            } else {
                Write-Host $line
            }
        }
    }
    Start-Sleep -Milliseconds 100
}
