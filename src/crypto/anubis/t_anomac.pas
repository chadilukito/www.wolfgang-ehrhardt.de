{-Test prog for Anubis-OMAC, we Aug.2008}
{ Reproduce Anubis part of Tom St Denis' OMAC_TV.TXT}

program t_anomac;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  ANU_Base, ANU_OMAC, Mem_Util;

const
  final: array[0..15] of byte = ($87,$b0,$c4,$8f,$3d,$15,$5a,$d8,
                                 $5d,$05,$02,$d9,$4a,$45,$72,$de);


{---------------------------------------------------------------------------}
procedure omac_tv;
var
  err, i, n: integer;
  key, tag: TANUBlock;
  inbuf: array[0..2*ANUBLKSIZE] of byte;
  ctx: TANUContext;
begin
  {Uppercase from HexStr}
  HexUpper := true;
  for i:=0 to ANUBLKSIZE-1 do key[i] := i;
  for n:=0 to 2*ANUBLKSIZE do begin
    for i:=0 to n-1 do inbuf[i] := i;
    err := ANU_OMAC_Init(key,8*ANUBLKSIZE,ctx);
    if err=0 then err := ANU_OMAC_Update(@inbuf,n,ctx);
    if err<>0 then begin
      writeln('ANU_OMAC error: ', err);
    end;
    ANU_OMAC_Final(tag,ctx);
    writeln(n:3,': ', HexStr(@tag,16));
    key := tag;
  end;
  if not compmem(@final,@tag, sizeof(final)) then writeln('Diff for final tag');
end;


begin
  omac_tv;
end.
