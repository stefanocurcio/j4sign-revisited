@echo off
if not exist %JAVA_HOME%\bin\java.exe goto notjava

%JAVA_HOME%\bin\java -cp lib\j4sign-installer.jar it.trento.comune.j4sign.installer.Installer
goto exit

:notjava
echo You have to set the JAVA_HOME evironment variable!

:exit
pause