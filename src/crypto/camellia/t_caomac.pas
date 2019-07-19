{-Test prog for Camellia-OMAC, we 09.2008}

program t_caomac;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  CAM_Base, CAM_OMAC, Mem_Util;

var
  writeIVal: boolean;

{---------------------------------------------------------------------------}
procedure omac_tv;
var
  err, i, n: integer;
  key, tag: TCAMBlock;
  inbuf: array[0..2*CAMBLKSIZE] of byte;
  ctx: TCAMContext;
const
  final: array[0..15] of byte = ($31,$E0,$4D,$E5,$F9,$D1,$40,$3C,$66,$E,$39,$89,$1D,$E0,$D8,$DE);
begin
  writeln('TSD format OMAC test vectors');
  {Uppercase from HexStr}
  HexUpper := true;
  for i:=0 to CAMBLKSIZE-1 do key[i] := i;
  for n:=0 to 2*CAMBLKSIZE do begin
    for i:=0 to n-1 do inbuf[i] := i;
    err := CAM_OMAC_Init(key,8*CAMBLKSIZE,ctx);
    if err=0 then err := CAM_OMAC_Update(@inbuf,n,ctx);
    if err<>0 then begin
      writeln('CAM_OMAC error: ', err);
    end;
    CAM_OMAC_Final(tag,ctx);
    if writeIVal then writeln(n:3,': ', HexStr(@tag,16));
    key := tag;
  end;
  {Note: final is not tested against other implementations! Used for regression tests.}
  if compmem(@final,@tag, sizeof(final)) then writeln('Final tag: OK')
  else writeln('Diff for final tag');
end;


{---------------------------------------------------------------------------}
procedure drafttest;
const
  key: array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,$ab,$f7,$15,$88,$09,$cf,$4f,$3c);
  msg: array[0..63] of byte = ($6b,$c1,$be,$e2,$2e,$40,$9f,$96,
                               $e9,$3d,$7e,$11,$73,$93,$17,$2a,
                               $ae,$2d,$8a,$57,$1e,$03,$ac,$9c,
                               $9e,$b7,$6f,$ac,$45,$af,$8e,$51,
                               $30,$c8,$1c,$46,$a3,$5c,$e4,$11,
                               $e5,$fb,$c1,$19,$1a,$0a,$52,$ef,
                               $f6,$9f,$24,$45,$df,$4f,$9b,$17,
                               $ad,$2b,$41,$7b,$e6,$6c,$37,$10);

  ref: array[1..4] of TCAMBlock = (($ba,$92,$57,$82,$aa,$a1,$f5,$d9,$a0,$0f,$89,$64,$80,$94,$fc,$71),
                                   ($6d,$96,$28,$54,$a3,$b9,$fd,$a5,$6d,$7d,$45,$a9,$5e,$e1,$79,$93),
                                   ($5c,$18,$d1,$19,$cc,$d6,$76,$61,$44,$ac,$18,$66,$13,$1d,$9f,$22),
                                   ($c2,$69,$9a,$6e,$ba,$55,$ce,$9d,$93,$9a,$8a,$4e,$19,$46,$6e,$e9));

const
  mlen: array[1..4] of word = (0,16,40,64);
var
  i,err: integer;
  ctx: TCAMContext;
  tag: TCAMBlock;
begin
  writeln('Test against draft-kato-ipsec-camellia-cmac96and128-02');
  for i:=1 to 4 do begin
    err := CAM_OMAC_Init(key,8*sizeof(key),ctx);
    if err=0 then err := CAM_OMAC_Update(@msg,mlen[i],ctx);
    if err<>0 then begin
      writeln('CAM_OMAC error: ', err, ' for i=',i);
    end;
    CAM_OMAC_Final(tag,ctx);
    if not compmem(@ref[i],@tag, sizeof(tag)) then begin
      writeln('Diff for tag, i=',i);
    end;
  end;
  writeln('Done.');
end;



begin
  writeIVal := paramstr(1)<>'test';
  omac_tv;
  drafttest;
end.
