@echo off
title Push Secure Email Project to GitHub
echo ========================================================
echo   Pushing Secure Email System to GitHub...
echo ========================================================
echo.

cd /d "C:\Users\Asus\.gemini\antigravity\scratch\secure_email"

REM Use full path to git in case it's not yet in the user's terminal PATH
"C:\Program Files\Git\cmd\git.exe" push -u origin main

echo.
echo ========================================================
echo   Push Finished!
echo ========================================================
pause
