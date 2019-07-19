{-Test prog for Anubis-EAX, (c) we Aug.2008}
{ Reproduce Anubis part of Tom St Denis' EAX_TV.TXT}

program T_AN_EAX;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  ANU_Base, ANU_EAX, Mem_Util;



{---------------------------------------------------------------------------}
procedure test;
  {-Reproduce Anubis part of Tom St Denis' EAX_TV.TXT}
const
  hex32: array[1..32] of byte = ($00,$01,$02,$03,$04,$05,$06,$07,
                                 $08,$09,$0a,$0b,$0c,$0d,$0e,$0f,
                                 $10,$11,$12,$13,$14,$15,$16,$17,
                                 $18,$19,$1a,$1b,$1c,$1d,$1e,$1f);

  buf32: array[0..31] of byte = ($5e,$29,$cd,$b7,$d9,$69,$5a,$11,
                                 $00,$43,$e9,$c2,$60,$10,$4b,$df,
                                 $02,$0a,$3a,$2a,$13,$9d,$41,$12,
                                 $e9,$18,$ab,$58,$4b,$dd,$7e,$da);


 tag32: array[0.. 15] of byte = ($91,$33,$21,$3a,$a7,$bc,$f0,$62,
                                 $d2,$bd,$37,$f8,$66,$68,$3d,$3f);

var
  err,n: integer;
  ctx: TANU_EAXContext;
  key, tag: TANUBlock;
  buf: array[0..63] of byte;
begin
  {Uppercase from HexStr}
  HexUpper := true;
  {Initial key from hex32}
  move(hex32, key, sizeof(key));
  for n:=0 to 32 do begin
    err := ANU_EAX_Init(key, 128, hex32, n, ctx);
    if err=0 then err := ANU_EAX_Provide_Header(@hex32,n,ctx);
    if err=0 then err := ANU_EAX_Encrypt(@hex32, @buf, n, ctx);
    if err=0 then begin
      ANU_EAX_Final(tag, ctx);
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
