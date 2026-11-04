@echo off
setlocal
cd /d "%~dp0..\.."
set "ROOT=%CD%"

where python >nul 2>nul || (
    echo ERROR: python is not in PATH. Install Python 3.10+ first.
    pause
    exit /b 1
)

python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo Installing PyInstaller ...
    python -m pip install --disable-pip-version-check pyinstaller || (
        echo ERROR: pip install pyinstaller failed.
        pause
        exit /b 1
    )
)

echo Building lan-route-fixer.exe ...
python -m PyInstaller --noconfirm --clean --onefile ^
    --name lan-route-fixer ^
    --paths "%ROOT%\src\usr\lib\lan-route-fixer" ^
    --distpath "%ROOT%\dist\windows" ^
    --workpath "%ROOT%\build\windows" ^
    --specpath "%ROOT%\build\windows" ^
    "%ROOT%\tools\windows\entry.py"
if errorlevel 1 (
    echo ERROR: PyInstaller build failed.
    pause
    exit /b 1
)

echo.
echo Built: %ROOT%\dist\windows\lan-route-fixer.exe
echo.
echo Run "status" without Administrator; "fix" needs an elevated prompt:
echo   dist\windows\lan-route-fixer.exe status
echo   dist\windows\lan-route-fixer.exe fix
echo.
pause