{-Test prog for Blowfish-EAX, we Jun.2007}
{Reproduce Blowfish part of Tom St Denis' EAX_TV.TXT}

program T_BF_EAX;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  BF_Base, BF_EAX, Mem_Util;



{---------------------------------------------------------------------------}
procedure test;
  {-Reproduce Blowfish part of Tom St Denis' EAX_TV.TXT}
const
  hex32: array[1..32] of byte = ($00,$01,$02,$03,$04,$05,$06,$07,
                                 $08,$09,$0a,$0b,$0c,$0d,$0e,$0f,
                                 $10,$11,$12,$13,$14,$15,$16,$17,
                                 $18,$19,$1a,$1b,$1c,$1d,$1e,$1f);

  buf16: array[0..15] of byte = ($60,$a3,$15,$19,$3f,$58,$14,$4f,
                                 $57,$01,$d5,$47,$c7,$9f,$ee,$ed);

  tag16: array[0..7]  of byte = ($91,$2f,$db,$db,$05,$46,$7d,$f5);

var
  err,n: integer;
  ctx: TBF_EAXContext;
  key, tag: TBFBlock;
  buf: array[0..63] of byte;
begin
  {Uppercase from HexStr}
  HexUpper := true;
  {Initial key from hex32}
  move(hex32, key, sizeof(key));
  for n:=0 to 16 do begin
    err := BF_EAX_Init(key, 8, hex32, n, ctx);
    if err=0 then err := BF_EAX_Provide_Header(@hex32,n,ctx);
    if err=0 then err := BF_EAX_Encrypt(@hex32, @buf, n, ctx);
    if err=0 then begin
      BF_EAX_Final(tag, ctx);
      writeln(n:3,': ', HexStr(@buf,n), ', ', HexStr(@tag,sizeof(tag)));
      {key for step n>1 is the tag of the previous step repeated}
      key := tag;
    end
    else begin
      writeln('Error ',err);
      halt;
    end;
  end;
  {compare only final values}
  if not compmem(@buf16, @buf, sizeof(buf16)) then writeln('** Diff: buf16');
  if not compmem(@tag16, @tag, sizeof(tag16)) then writeln('** Diff: tag16');
end;

begin
  test;
end.
