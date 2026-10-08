@echo off

echo ----------------------------------------
echo Installing PyInstaller...
echo ----------------------------------------
.\.venv\Scripts\pip install pyinstaller

echo.
echo ----------------------------------------
echo Building MyLocker Portable...
echo ----------------------------------------
.\.venv\Scripts\pyinstaller --noconfirm --onedir --windowed ^
    --add-data "mlcore\mlcore.dll;mlcore" ^
    --icon NONE ^
    --name MyLocker ^
    gui\app.py

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b %ERRORLEVEL%
)

echo.
echo ----------------------------------------
echo Build Succeeded!
echo Portable application is located in "dist\MyLocker"
echo ----------------------------------------
