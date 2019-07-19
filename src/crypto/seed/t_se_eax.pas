{-Test prog for SEED-EAX, we Jun.2007}
{Reproduce SEED part of Tom St Denis' EAX_TV.TXT}

program T_SE_EAX;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  SEA_Base, SEA_EAX, Mem_Util;



{---------------------------------------------------------------------------}
procedure test;
  {-Reproduce SEED part of Tom St Denis' EAX_TV.TXT}
const
  hex32: array[1..32] of byte = ($00,$01,$02,$03,$04,$05,$06,$07,
                                 $08,$09,$0a,$0b,$0c,$0d,$0e,$0f,
                                 $10,$11,$12,$13,$14,$15,$16,$17,
                                 $18,$19,$1a,$1b,$1c,$1d,$1e,$1f);

  buf32: array[0..31] of byte = ($21,$dc,$38,$be,$25,$2e,$cc,$a7,
                                 $49,$63,$96,$56,$60,$c9,$8b,$5d,
                                 $9b,$5c,$24,$11,$94,$5d,$8a,$af,
                                 $9e,$f9,$37,$32,$74,$8a,$61,$62);

 tag32: array[0.. 15] of byte = ($2b,$be,$55,$5f,$1d,$3c,$94,$bc,
                                 $6f,$16,$65,$a6,$de,$db,$53,$6c);

var
  err,n: integer;
  ctx: TSEA_EAXContext;
  key, tag: TSEABlock;
  buf: array[0..63] of byte;
begin
  {Uppercase from HexStr}
  HexUpper := true;
  {Initial key from hex32}
  move(hex32, key, sizeof(key));
  for n:=0 to 32 do begin
    err := SEA_EAX_Init(key, 128, hex32, n, ctx);
    if err=0 then err := SEA_EAX_Provide_Header(@hex32,n,ctx);
    if err=0 then err := SEA_EAX_Encrypt(@hex32, @buf, n, ctx);
    if err=0 then begin
      SEA_EAX_Final(tag, ctx);
      writeln(n:3,': ', HexStr(@buf,n), ', ', HexStr(@tag,16));
      {key for step n>1 is the tag of the previous step repeated}
      key := tag;
    end
    else begin
      writeln('Error ',err);
      halt;
    end;
  end;
  {compare only final values}
  if not compmem(@buf32, @buf, sizeof(buf32)) then writeln('** Diff: buf32');
  if not compmem(@tag32, @tag, sizeof(tag32)) then writeln('** Diff: tag32');
end;

begin
  test;
end.
