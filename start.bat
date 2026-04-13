@echo off
title KeyAuth Server
color 0a

echo ========================================
echo    KeyAuth Server Starter
echo ========================================
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed!
    echo.
    echo Please download and install Node.js from:
    echo https://nodejs.org
    echo.
    pause
    exit /b 1
)

echo [OK] Node.js is installed

REM Install dependencies if needed
if not exist "node_modules" (
    echo.
    echo Installing dependencies...
    npm install
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
    echo [OK] Dependencies installed
) else (
    echo [OK] Dependencies already installed
)

echo.
echo ========================================
echo Starting server...
echo ========================================
echo.
echo Dashboard: http://localhost:3000/keyauth.html
echo API:       http://localhost:3000/api/auth/validate
echo.
echo Opening browser...
start http://localhost:3000/keyauth.html
echo.
echo ========================================
echo Server is running! Press Ctrl+C to stop
echo ========================================
echo.

node keyauth-server.js

pause
