@echo off
set "PATH=C:\Users\amart\AppData\Local\Programs\MinGit\cmd;C:\Users\amart\AppData\Local\Programs\MinGit\mingw64\bin;%PATH%"
echo ====================================================
echo Pushing NEXUS-SHIELD to GitHub...
echo ====================================================
git remote set-url origin https://github.com/amarthalurisrinivasu085-a11y/Nexus-Shield.git
git push -u origin main
echo.
if %ERRORLEVEL% EQU 0 (
    echo ====================================================
    echo [SUCCESS] Successfully pushed to:
    echo https://github.com/amarthalurisrinivasu085-a11y/Nexus-Shield
    echo ====================================================
) else (
    echo [ERROR] Push failed. Please check your GitHub credentials.
)
pause
