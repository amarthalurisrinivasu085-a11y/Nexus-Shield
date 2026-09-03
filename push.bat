@echo off
set "PATH=C:\Users\amart\AppData\Local\Programs\MinGit\cmd;%PATH%"
echo ====================================================
echo Pushing NEXUS-SHIELD to GitHub...
echo ====================================================
git push -u origin main
echo.
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Pushed to https://github.com/amarthalurisrinivasu085-a11y/nexus-shield
) else (
    echo [NOTE] If you haven't created the repository yet, create it at:
    echo        https://github.com/new?name=nexus-shield
)
pause
