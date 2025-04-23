@echo off
setlocal enabledelayedexpansion

:: ========================================
::  CONFIGURATION
:: ========================================
set APP_NAME=ArchivePasswordCrackerCLI
:: --- UPDATED: Version Number ---
set VERSION=v1.2.0
set SRC_DIR=src
set OUT_EXE=%APP_NAME%.exe
set RELEASE_DIR=archive-password-cracker-cli-%VERSION%
set BIN_DIR=%RELEASE_DIR%\bin

:: --- !! ADJUST THESE PATHS !! ---
set MINGW_ROOT=D:\Apps\msys64\mingw64
set SEVENZIP_DIR=C:\Program Files\7-Zip
:: --- End Adjust ---

set MINGW_BIN=%MINGW_ROOT%\bin
set INCLUDE_DIR=%MINGW_ROOT%\include
set LIB_DIR=%MINGW_ROOT%\lib

:: --- UPDATED: Compiler name with extension for checks/execution ---
set COMPILER_EXE=g++.exe

:: Files required from 7-Zip (go into bin/ relative to the *output* exe)
set SEVENZIP_FILES=7z.exe 7z.dll

echo.
echo =====================================
echo  Building: %APP_NAME% %VERSION% (CLI + C++)
echo =====================================

:: ========================================
::  CHECK COMPILER (Added for robustness, uses COMPILER_EXE)
:: ========================================
if not exist "%MINGW_BIN%\%COMPILER_EXE%" (
    echo [ERROR] MinGW compiler not found at: "%MINGW_BIN%\%COMPILER_EXE%"
    echo Please check the MINGW_ROOT variable in this script.
    pause
    exit /b 1
)

:: ========================================
::  PREPARE RELEASE FOLDER (Structure kept identical)
:: ========================================
if exist "%RELEASE_DIR%" (
    echo Removing old release directory: %RELEASE_DIR%
    rmdir /s /q "%RELEASE_DIR%" > nul 2>&1
    if errorlevel 1 (
        echo [WARN] Failed to remove old directory "%RELEASE_DIR%". Maybe in use?
    )
)
echo Creating release directory: %RELEASE_DIR%
mkdir "%RELEASE_DIR%"
if errorlevel 1 (
    echo [ERROR] Failed to create directory "%RELEASE_DIR%". Check permissions.
    pause
    exit /b 1
)
echo Creating bin directory: %RELEASE_DIR%\bin
mkdir "%BIN_DIR%"
if errorlevel 1 (
    echo [ERROR] Failed to create directory "%BIN_DIR%". Check permissions.
    pause
    exit /b 1
)

:: ========================================
::  COMPILATION (output directly into release folder)
:: ========================================
echo Compiling C++ source...
REM Add -static flags to try and link runtime statically, reducing DLL dependencies
REM --- UPDATED: Added bloom_filter.cpp and use COMPILER_EXE variable ---
"%MINGW_BIN%\%COMPILER_EXE%" "%SRC_DIR%\main.cpp" "%SRC_DIR%\brute_force.cpp" "%SRC_DIR%\bloom_filter.cpp" ^
    -o "%RELEASE_DIR%\%OUT_EXE%" ^
    -I"%SRC_DIR%" ^
    -I"%INCLUDE_DIR%" -L"%LIB_DIR%" ^
    -std=c++17 -pthread -O3 -Wall -Wextra ^
    -lshlwapi -static-libgcc -static-libstdc++ -static -lpthread

if errorlevel 1 (
    echo.
    echo [ERROR] Compilation FAILED! Check compiler output.
    pause
    exit /b 1
)

echo.
echo [OK]    Compilation successful: %OUT_EXE% -^> %RELEASE_DIR%\

:: ========================================
::  COPY 7-Zip FILES (to bin/ inside release folder) (Structure kept identical)
:: ========================================
echo Copying 7-Zip files...
set SEVENZIP_COPY_ERROR=0
for %%f in (%SEVENZIP_FILES%) do (
    if exist "%SEVENZIP_DIR%\%%f" (
        copy /Y "%SEVENZIP_DIR%\%%f" "%BIN_DIR%\" >nul
        if errorlevel 1 (
           echo [ERROR] Failed to copy %%f to %BIN_DIR%\
           set SEVENZIP_COPY_ERROR=1
        ) else (
           echo [OK]    Copied: %%f
        )
    ) else (
        echo [WARN]  7-Zip file not found: "%SEVENZIP_DIR%\%%f" (Needed by %OUT_EXE%)
        set SEVENZIP_COPY_ERROR=1
    )
)
if %SEVENZIP_COPY_ERROR% equ 1 (
    echo [WARN] One or more 7-Zip files could not be found or copied. The backend might not run correctly.
)

echo.
echo [DONE] Release package is ready in '%RELEASE_DIR%'
echo        You need to copy '%RELEASE_DIR%\%OUT_EXE%'
echo        to the main project's 'helpers' folder ('%~dp0..\helpers\')
echo.
echo        The C++ executable expects the *main project's* 'bin' folder containing 7z.exe/dll
echo        (e.g., '%~dp0..\bin\') relative to the 'helpers' folder where it runs.
echo.

pause
endlocal