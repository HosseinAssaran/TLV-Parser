@echo off
setlocal enabledelayedexpansion

set "CARGO_TOML=Cargo.toml"

for /f "usebackq tokens=1,* delims==" %%a in (`findstr /r "^version" "%CARGO_TOML%"`) do (
    set VERSION=%%b
    set VERSION=!VERSION:~2,-1!
    echo The version in %CARGO_TOML% is: !VERSION!
)

REM Set the URL of the file to download
set "url=https://github.com/HosseinAssaran/TLV-Parser/releases/download/v!VERSION!/emv_tlv_parser.exe"

REM Set the absolute destination path for the downloaded file
set "target_dir=%~dp0\\target\\release"
echo %target_dir%
set "destination=%target_dir%\\emv_tlv_parser.exe"
md  %target_dir% 2>nul

REM Download the file using bitsadmin
bitsadmin /transfer myDownloadJob /download /priority normal %url% %destination%

REM Wait for the download to complete (optional)
REM timeout /t 10 /nobreak

echo Download complete.
