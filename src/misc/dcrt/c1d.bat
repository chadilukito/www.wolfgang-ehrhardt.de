@echo off
::build crt for Delphi Version %1 dcc32
call b%1 crt
md M%1
move crt.dcu M%1
attrib +r M%1\crt.dcu
