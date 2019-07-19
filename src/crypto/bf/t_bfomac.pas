{-Test prog for Blowfish-OMAC, we 2007-2017}
{Reproduce Blowfish part of Tom St Denis' OMAC_TV.TXT}

program t_bfomac;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  BF_Base, BF_OMAC, Mem_Util;

const
  final: array[0..7] of byte = ($8e,$68,$31,$d5,$37,$06,$78,$ef);

{---------------------------------------------------------------------------}
procedure omac_tv;
var
  err, i, n: integer;
  key, tag: TBFBlock;
  inbuf: array[0..2*BFBLKSIZE] of byte;
  ctx: TBFContext;
begin
  {Uppercase from HexStr}
  HexUpper := true;
  for i:=0 to BFBLKSIZE-1 do key[i] := i;
  for n:=0 to 2*BFBLKSIZE do begin
    for i:=0 to n-1 do inbuf[i] := i;
    err := BF_OMAC_Init(key,BFBLKSIZE,ctx);
    if err=0 then err := BF_OMAC_Update(@inbuf,n,ctx);
    if err<>0 then begin
      writeln('BF_OMAC error: ', err);
    end;
    BF_OMAC_Final(tag,ctx);
    writeln(n:3,': ', HexStr(@tag,sizeof(tag)));
    key := tag;
  end;
  if not compmem(@final,@tag, sizeof(final)) then writeln('Diff for final tag');
end;


begin
  omac_tv;
end.

