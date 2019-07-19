@echo off
if not (%2)==() goto usage

::batch to build minizip/miniunz for different compilers
::(C) W.Ehrhardt 2005-2008
::assumes zlib in parent directory
::please adjust dcc32 path directories

:bp
if not (%1)==(bp) goto bpdpmi
bpc -b -U.. -I.. minizip.pas
bpc -b -U.. -I.. miniunz.pas
goto end

:bpdpmi
if not (%1)==(bpdpmi) goto vpc
bpc -b -cp -U.. -I.. minizip.pas
bpc -b -cp -U.. -I.. miniunz.pas
goto end

:vpc
if not (%1)==(vpc) goto fpc2
vpc -b -U.. -I.. minizip.pas
vpc -b -U.. -I.. miniunz.pas
goto end

:fpc2
if not (%1)==(fpc2) goto fpc22
call fpc2 -B -Fu.. -Fi.. minizip.pas
call fpc2 -B -Fu.. -Fi.. miniunz.pas
goto end

:fpc22
if not (%1)==(fpc22) goto fpc222
call fpc22 -B -Fu.. -Fi.. minizip.pas
call fpc22 -B -Fu.. -Fi.. miniunz.pas
goto end

:fpc222
if not (%1)==(fpc222) goto fpc224
call fpc222 -B -Fu.. -Fi.. minizip.pas
call fpc222 -B -Fu.. -Fi.. miniunz.pas
goto end

:fpc224
if not (%1)==(fpc224) goto d2
call fpc224 -B -Fu.. -Fi.. minizip.pas
call fpc224 -B -Fu.. -Fi.. miniunz.pas
goto end

:d2
if not (%1)==(d2) goto d3
d:\dmx\m2\dcc32.exe -b -U.. -I.. minizip.pas
d:\dmx\m2\dcc32.exe -b -U.. -I.. miniunz.pas
goto end

:d3
if not (%1)==(d3) goto d4
d:\dmx\m3\dcc32.exe -b -U.. -I.. minizip.pas
d:\dmx\m4\dcc32.exe -b -U.. -I.. miniunz.pas
goto end

:d4
if not (%1)==(d4) goto d5
d:\dmx\m4\dcc32.exe -b -U.. -I.. minizip.pas
d:\dmx\m4\dcc32.exe -b -U.. -I.. miniunz.pas
goto end

:d5
if not (%1)==(d5) goto d6
d:\dmx\m5\dcc32.exe -b -U.. -I.. minizip.pas
d:\dmx\m5\dcc32.exe -b -U.. -I.. miniunz.pas
goto end

:d6
if not (%1)==(d6) goto d7
d:\dmx\m6\dcc32.exe -b -U.. -I.. minizip.pas
d:\dmx\m6\dcc32.exe -b -U.. -I.. miniunz.pas
goto end

:d7
if not (%1)==(d7) goto d9
d:\dmx\m7\dcc32.exe -b -U.. -I.. minizip.pas
d:\dmx\m7\dcc32.exe -b -U.. -I.. miniunz.pas
goto end

:d9
if not (%1)==(d9) goto d10
d:\dmx\m9\dcc32.exe -b -U.. -I.. minizip.pas
d:\dmx\m9\dcc32.exe -b -U.. -I.. miniunz.pas
goto end

:d10
if not (%1)==(d10) goto d12
d:\dmx\m10\dcc32.exe -b -U.. -I.. minizip.pas
d:\dmx\m10\dcc32.exe -b -U.. -I.. miniunz.pas
goto end

:d12
if not (%1)==(d12) goto usage
d:\dmx\m12\dcc32.exe -b -U.. -I.. minizip.pas
d:\dmx\m12\dcc32.exe -b -U.. -I.. miniunz.pas
goto end

:usage
echo usage: %0 {compiler}
echo        compler: bp, bpdpmi, vpc, fpc2, fpc22, fpc222, fpc224
echo                 d2, d3, d4, d5, d6, d7, d9, d10, d12

:end
