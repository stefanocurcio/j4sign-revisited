@echo off
if not exist %JAVA_HOME%\bin\java.exe goto notjava

%JAVA_HOME%\bin\java -cp lib\j4sign-core.jar;lib\bcmail-jdk16-145.jar;lib\bcprov-jdk16-145.jar it.trento.comune.j4sign.examples.GUITest %1
goto exit
:notjava
echo You have to set the JAVA_HOME evironment variable!

:exit
pause