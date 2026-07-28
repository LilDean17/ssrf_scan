@echo off
echo Compiling Burp Suite SSRF Scanner (ceye.io) Plugin...

REM 设置Burp Suite的jar路径（请根据实际情况修改）
set BURP_JAR=C:\BurpSuitePro\burpsuite_pro.jar

if not exist "%BURP_JAR%" (
    echo Error: Burp Suite jar not found at %BURP_JAR%
    echo Please modify BURP_JAR variable in compile.bat to point to your Burp Suite installation
    pause
    exit /b 1
)

REM 编译Java文件到当前目录
javac -cp "%BURP_JAR%" -d . src\main\java\burp\BurpExtender.java

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Compilation successful!
    echo.
    echo Creating JAR file...
    jar cf ssrf-scan.jar burp\BurpExtender*.class

    if exist "ssrf-scan.jar" (
        echo JAR file created at: ssrf-scan.jar
        echo.
        echo To use this plugin:
        echo 1. Open Burp Suite
        echo 2. Go to Extender - Extensions
        echo 3. Add this JAR file
        echo 4. The SSRF Scanner tab will appear
    ) else (
        echo Error: Failed to create JAR file
    )
) else (
    echo.
    echo Compilation failed!
    echo Please check the error messages above
)

pause
