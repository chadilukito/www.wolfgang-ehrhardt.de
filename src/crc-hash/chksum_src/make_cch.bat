@echo off
call fpc300 -B -O4 cch.pas
::upx -9 cch.exe