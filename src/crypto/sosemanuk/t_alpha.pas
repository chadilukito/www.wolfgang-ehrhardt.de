program t_alpha;

{Calculate mulAlpha and divAlpha tables for Sosemanuk,  WE Apr.2009}

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
    wincrt,
  {$endif}
  mem_util;

var
  mulAlpha, divAlpha: array[0..255] of longint;
  logb,expb: array[0..255] of byte;

{---------------------------------------------------------------------------}
procedure CalcAlphaTables;
var
  i: integer;
  x: word;
begin
  x := 1;
  for i:=0 to 254 do begin
    expb[i] := byte(x);
    x := x shl 1;
    if x > $FF then x := x xor $1A9;
  end;
  expb[255] := 0;
  for i:=0 to 255 do logb[expb[i]] := i;
  mulAlpha[0] := 0;
  divAlpha[0] := 0;
  for i:=1 to 255 do begin
    x := logb[i];
    mulAlpha[i] := longint(expb[(x+ 23) mod 255]) shl 24 or
                   longint(expb[(x+245) mod 255]) shl 16 or
                   longint(expb[(x+ 48) mod 255]) shl 08 or
                   longint(expb[(x+239) mod 255]);
    divAlpha[i] := longint(expb[(x+ 16) mod 255]) shl 24 or
                   longint(expb[(x+ 39) mod 255]) shl 16 or
                   longint(expb[(x+  6) mod 255]) shl 08 or
                   longint(expb[(x+ 64) mod 255]);

  end;
end;


{---------------------------------------------------------------------------}
procedure DumpAlphaTables;
var
  i,j: integer;
begin
  HexUpper := false;
  writeln('const');
  writeln('  mulAlpha: array[0..255] of longint = (');
  for i:=0 to 31 do begin
    write('    ');
    for j:=0 to 7 do begin
      write('$',HexLong(mulAlpha[8*i+j]));
      if (i=31) and (j=7) then writeln(');') else write(',');
    end;
    writeln;
  end;
  writeln('const');
  writeln('  divAlpha: array[0..255] of longint = (');
  for i:=0 to 31 do begin
    write('    ');
    for j:=0 to 7 do begin
      write('$',HexLong(divAlpha[8*i+j]));
      if (i=31) and (j=7) then writeln(');') else write(',');
    end;
    writeln;
  end;
end;


begin
  CalcAlphaTables;
  DumpAlphaTables;
end.

