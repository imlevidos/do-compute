:: Script to start ConEmu in the folder specified by %1, similar to `code .`
:: Expects ConEmuPortable.exe in %PATH%
:: https://github.com/levid0s

@ECHO OFF

if [%1] == [] (SET STARTDIR=%CD~%) ELSE (SET STARTDIR=%~1)

set DIRSUFFIX=%STARTDIR:~0,1%

if [%DIRSUFFIX%] == [.] (
	:: We have a RELATIVE dir
	set ABSPATH=%CD%\%STARTDIR%
	GOTO Run
)
if [%DIRSUFFIX%] == [\] (
	REM We have LOCAL ROOT path
	set ABSPATH=%CD:~0,2%%STARTDIR%
	GOTO Run
)
if [%DIRSUFFIX%] == [/] (
	REM We have LOCAL ROOT path
	set ABSPATH=%CD:~0,2%%STARTDIR%
	GOTO Run
)
:: ELSE - We have an ABSOLUTE path
set ABSPATH=%STARTDIR%
GOTO Run

:Run
:: ConEmuPortable.exe -Dir 'C:\Program Files\Windows Defender\' -run "{Shells::PowerShellHere}"

ConEmuPortable.exe -Dir "%ABSPATH%" -run "{Shells::PowerShellHere}"

:: RESOURCES:
::	https://www.robvanderwoude.com/escapechars.php
::	https://stackoverflow.com/questions/14954271/string-comparison-in-batch-file
::	https://stackoverflow.com/questions/36857098/extract-first-character-from-a-string
::	https://stackoverflow.com/questions/1645843/resolve-absolute-path-from-relative-path-and-or-file-name/4488734#4488734
::	https://stackoverflow.com/questions/25384358/batch-if-elseif-else
::	https://stackoverflow.com/questions/2541767/what-is-the-proper-way-to-test-if-a-parameter-is-empty-in-a-batch-file
:: 	https://stackoverflow.com/questions/47426129/difference-between-1-and-1-in-batch
