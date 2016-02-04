@echo off
if not exist %JAVA_HOME%\bin\java.exe goto notjava

%JAVA_HOME%\bin\java -cp lib\* it.trento.comune.j4sign.examples.CLITest "%1" "%2"
goto exit
:notjava
echo You have to set the JAVA_HOME evironment variable!

:exit
pause