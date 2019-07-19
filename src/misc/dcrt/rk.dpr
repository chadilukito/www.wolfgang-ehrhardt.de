{Test program for Delphi-CRT and reference with BP7-CRT, (c) WE 2006}
{Test readkey scan codes and line editing keys}

program rk;

{$ifdef WIN32}
{$ifndef VirtualPascal}
{$apptype console}
{$endif}
{$endif}

{$ifdef WIN64}
{$apptype console}
{$endif}

{$X+}

uses
  crt;
var
  c: ansichar;
  s: ansistring;
begin
  {$ifdef VER90}
    InitCRT;
  {$endif}
  TextMode(CO80+Font8x8);
  repeat
    c := readkey;
    write('#',ord(c),'[',c,']');
  until c=#27;
  writeln;
  write('Enter string:' );
  readln(s);
  writeln(s);
  Readkey;
end.
