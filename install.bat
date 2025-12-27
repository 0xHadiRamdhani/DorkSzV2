@echo off
REM DorkSz Installation Script for Windows
REM Author: HadsXdevPy

setlocal enabledelayedexpansion

REM Colors (using ANSI escape codes if supported)
set RED=[31m
set GREEN=[32m
set YELLOW=[33m
set BLUE=[34m
set WHITE=[37m
set NC=[0m

REM Banner
echo %RED%
echo   ______                    __      _______         
echo  ^|   _  \   .-----. .----. ^|  ^|--. ^|   _   ^| .-----.
echo  ^|.  ^|   \  ^|  _  ^| ^|   _^| ^|    ^<  ^|___^|   ^| ^|__ --^|
echo  ^|.  ^|    \ ^|_____^| ^|__^|   ^|__^|__^|  /  ___/  ^|_____^|
echo  ^|:  1    /                        ^|:  1  \         
echo  ^|::.. . /                         ^|::.. . ^|        
echo  `------'                          `-------'        
echo %NC%
echo %YELLOW%DorkSz Installation Script%NC%
echo %YELLOW%Author: HadsXdevPy%NC%
echo.

REM Check if Python is installed
echo %BLUE%[INFO] Checking Python installation...%NC%
python --version >nul 2>&1
if !errorlevel! equ 0 (
    for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
    echo %GREEN%[✓] Python found: !PYTHON_VERSION!%NC%
) else (
    echo %RED%[ERROR] Python is not installed!%NC%
    echo %YELLOW%Please install Python 3.6 or higher and try again.%NC%
    pause
    exit /b 1
)

REM Check if pip is available
echo %BLUE%[INFO] Checking pip...%NC%
python -m pip --version >nul 2>&1
if !errorlevel! equ 0 (
    echo %GREEN%[✓] pip found%NC%
) else (
    echo %RED%[ERROR] pip is not available!%NC%
    echo %YELLOW%Please ensure pip is installed with Python.%NC%
    pause
    exit /b 1
)

REM Upgrade pip
echo %BLUE%[INFO] Upgrading pip...%NC%
python -m pip install --upgrade pip
if !errorlevel! neq 0 (
    echo %YELLOW%[WARNING] Could not upgrade pip, continuing anyway...%NC%
)

REM Install dependencies
echo %BLUE%[INFO] Installing dependencies...%NC%
if exist "requirements.txt" (
    python -m pip install -r requirements.txt
    if !errorlevel! equ 0 (
        echo %GREEN%[✓] Dependencies installed%NC%
    ) else (
        echo %RED%[ERROR] Failed to install dependencies%NC%
        pause
        exit /b 1
    )
) else (
    echo %RED%[ERROR] requirements.txt not found!%NC%
    pause
    exit /b 1
)

REM Test installation
echo %BLUE%[INFO] Testing installation...%NC%
python -c "import googlesearch, requests; print('Import test passed')" >nul 2>&1
if !errorlevel! equ 0 (
    echo %GREEN%[✓] Installation test passed%NC%
) else (
    echo %RED%[ERROR] Installation test failed!%NC%
    pause
    exit /b 1
)

REM Create batch file for easy activation
echo %BLUE%[INFO] Creating activation script...%NC%
(
echo @echo off
echo REM DorkSz Activation Script
echo.
echo echo DorkSz environment ready!
echo echo You can now run: python DorkSz.py --help
echo echo.
echo echo Current directory: %~dp0
echo.
echo python DorkSz.py --help
echo.
echo echo Press any key to continue...
echo pause ^>nul
) > activate_dorksz.bat

REM Create desktop shortcut (if possible)
echo %BLUE%[INFO] Creating desktop shortcut...%NC%
set DESKTOP=%USERPROFILE%\Desktop
if exist "%DESKTOP%" (
    (
    echo [InternetShortcut]
    echo URL=file:///%~dp0DorkSz.py
    echo IconFile=cmd.exe
    echo IconIndex=0
    ) > "%DESKTOP%\DorkSz.url"
    echo %GREEN%[✓] Desktop shortcut created%NC%
) else (
    echo %YELLOW%[WARNING] Could not create desktop shortcut%NC%
)

REM Final message
echo.
echo %GREEN%[✓] Installation completed successfully!%NC%
echo.
echo %YELLOW%=== Usage Instructions ===%NC%
echo %WHITE%# To use DorkSz:%NC%
echo %BLUE%python DorkSz.py --help%NC%
echo.
echo %WHITE%# Or use the activation script:%NC%
echo %BLUE%activate_dorksz.bat%NC%
echo.
echo %WHITE%# Example usage:%NC%
echo %BLUE%python DorkSz.py -d "inurl:admin.php?id=" -o results.txt%NC%
echo.
echo %YELLOW%Happy scanning! Remember to use responsibly.%NC%
echo %YELLOW%Only test websites you own or have permission to test.%NC%

pause