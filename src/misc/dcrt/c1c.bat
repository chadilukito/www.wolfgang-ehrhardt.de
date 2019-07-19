@echo off
::build crt for BCB Version %1 dcc32
call bcb%1 crt
md BCB%1
move crt.dcu BCB%1
attrib +r BCB%1\crt.dcu
