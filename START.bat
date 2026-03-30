@echo off
setlocal

echo.
echo ====================================================
echo   Locked Firewall Rule Reviewer
echo ====================================================
echo.

:: ── Backend ────────────────────────────────────────────────────
echo [Backend] Starting FastAPI on http://localhost:8000 ...

if not exist ".env" (
    copy .env.example .env
    echo    Created .env from .env.example
)

:: Check for python/pip
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo    Error: Python not found. Please install Python 3.10+ and add to PATH.
    pause
    exit /b 1
)

:: Install deps if needed (simple check)
if not exist ".venv" (
    echo    Creating virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

echo    Installing Python dependencies...
pip install -r requirements.txt --quiet --disable-pip-version-check

start "Firewall Backend" cmd /k "python main.py"

:: Wait a bit for backend
timeout /t 5 >nul

:: ── Frontend ───────────────────────────────────────────────────
echo.
echo [Frontend] Starting React on http://localhost:8080 ...
cd fortress-lens-main

if not exist "node_modules" (
    echo    Installing Node dependencies...
    call npm install --silent
)

start "Firewall Frontend" cmd /k "npm run dev"

:: ── Done ───────────────────────────────────────────────────────
echo.
echo ====================================================
echo   Both services are starting...
echo.
echo   Frontend  -  http://localhost:8080
echo   Backend   -  http://localhost:8000
echo   API Docs  -  http://localhost:8000/docs
echo.
echo   Close the opened command windows to stop services.
echo ====================================================
echo.
pause
