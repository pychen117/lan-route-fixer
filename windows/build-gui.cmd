@echo off
setlocal
cd /d "%~dp0.."
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

echo Building lan-route-fixer-gui.exe ...
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name lan-route-fixer-gui ^
    --icon "%ROOT%\windows\lanrf.ico" ^
    --add-data "%ROOT%\windows\lanrf.ico;." ^
    --paths "%ROOT%\src\usr\lib\lan-route-fixer" ^
    --distpath "%ROOT%\dist\windows" ^
    --workpath "%ROOT%\build\windows" ^
    --specpath "%ROOT%\build\windows" ^
    "%ROOT%\windows\gui_entry.py"
if errorlevel 1 (
    echo ERROR: PyInstaller build failed.
    pause
    exit /b 1
)

echo.
echo Built: %ROOT%\dist\windows\lan-route-fixer-gui.exe
echo.
echo Double-click it for the GUI. The same binary also runs the CLI modes:
echo   dist\windows\lan-route-fixer-gui.exe run --interval 10
echo.
pause