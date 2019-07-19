{-Test prog for Camellia-EAX, we 06.2008}
{-Camellia EAX test vectors, format from Tom St Denis' EAX_TV.TXT}

program T_CA_EAX;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  {$ifdef USEDLL}
    {$ifdef VirtualPascal}
      CAM_Intv,
    {$else}
      CAM_Intf,
    {$endif}
  {$else}
    CAM_Base, CAM_EAX,
  {$endif}

  Mem_Util;



{---------------------------------------------------------------------------}
procedure test;
  {-Camellia EAX test vectors, format from Tom St Denis' EAX_TV.TXT}
const
  hex32: array[1..32] of byte = ($00,$01,$02,$03,$04,$05,$06,$07,
                                 $08,$09,$0a,$0b,$0c,$0d,$0e,$0f,
                                 $10,$11,$12,$13,$14,$15,$16,$17,
                                 $18,$19,$1a,$1b,$1c,$1d,$1e,$1f);

  buf32: array[0..31] of byte = ($8e,$6e,$64,$33,$e4,$ff,$87,$91,
                                 $55,$e0,$61,$2f,$17,$ef,$c0,$0a,
                                 $a8,$d5,$23,$6e,$fa,$b5,$d9,$d6,
                                 $a9,$12,$89,$8f,$31,$24,$b5,$88);

  tag32: array[0..15] of byte = ($ed,$f8,$1b,$b7,$3f,$f9,$28,$8f,
                                 $31,$5b,$98,$84,$13,$43,$28,$23);

var
  err,n: integer;
  ctx: TCAM_EAXContext;
  key, tag: TCAMBlock;
  buf: array[0..63] of byte;
begin
  {Uppercase from HexStr}
  HexUpper := true;
  {Initial key from hex32}
  move(hex32, key, sizeof(key));
  for n:=0 to 32 do begin
    err := CAM_EAX_Init(key, 128, hex32, n, ctx);
    if err=0 then err := CAM_EAX_Provide_Header(@hex32,n,ctx);
    if err=0 then err := CAM_EAX_Encrypt(@hex32, @buf, n, ctx);
    if err=0 then begin
      CAM_EAX_Final(tag, ctx);
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
