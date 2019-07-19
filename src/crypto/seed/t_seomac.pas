{-Test prog for SEED-OMAC, we Jun.2007}
{Reproduce SEED part of Tom St Denis' OMAC_TV.TXT}

program t_seomac;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  SEA_Base, SEA_OMAC, Mem_Util;

const
  final: array[0..15] of byte = ($c7,$16,$24,$31,$a5,$32,$16,$c2,
                                 $2d,$47,$fa,$51,$1b,$0a,$61,$9e);


{---------------------------------------------------------------------------}
procedure omac_tv;
var
  err, i, n: integer;
  key, tag: TSEABlock;
  inbuf: array[0..2*SEABLKSIZE] of byte;
  ctx: TSEAContext;
begin
  {Uppercase HexStr}
  HexUpper := true;
  for i:=0 to SEABLKSIZE-1 do key[i] := i;
  for n:=0 to 2*SEABLKSIZE do begin
    for i:=0 to n-1 do inbuf[i] := i;
    err := SEA_OMAC_Init(key,8*SEABLKSIZE,ctx);
    if err=0 then err := SEA_OMAC_Update(@inbuf,n,ctx);
    if err<>0 then begin
      writeln('SEA_OMAC error: ', err);
    end;
    SEA_OMAC_Final(tag,ctx);
    writeln(n:3,': ', HexStr(@tag,16));
    key := tag;
  end;
  if not compmem(@final,@tag, sizeof(final)) then writeln('Diff for final tag')
  else writeln('OK.');
end;


begin
  omac_tv;
end.
