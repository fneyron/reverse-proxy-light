@echo off
setlocal

if not exist "%~dp0local-proxy-go.exe" (
  call "%~dp0build.bat"
)

set /p PROXY_TARGET=PROXY_TARGET (ex: https://votre-domaine-pages) :
set /p PROXY_TOKEN=PROXY_TOKEN :
set /p LOCAL_PROXY_PORT=LOCAL_PROXY_PORT (default 8080) :
set /p UPSTREAM_PROXY=UPSTREAM_PROXY (optionnel, ex: http://proxy:8080) :
set /p PROXY_CONFIG=PROXY_CONFIG (optionnel, ex: proxy-config.yaml) :

if "%LOCAL_PROXY_PORT%"=="" set LOCAL_PROXY_PORT=8080

set PROXY_TARGET=%PROXY_TARGET%
set PROXY_TOKEN=%PROXY_TOKEN%
set LOCAL_PROXY_PORT=%LOCAL_PROXY_PORT%

set UPSTREAM_ARG=
if not "%UPSTREAM_PROXY%"=="" set UPSTREAM_ARG=-upstream "%UPSTREAM_PROXY%"
set CONFIG_ARG=
if not "%PROXY_CONFIG%"=="" set CONFIG_ARG=-config "%PROXY_CONFIG%"

"%~dp0local-proxy-go.exe" -target "%PROXY_TARGET%" -token "%PROXY_TOKEN%" -port "%LOCAL_PROXY_PORT%" %UPSTREAM_ARG% %CONFIG_ARG%
endlocal
