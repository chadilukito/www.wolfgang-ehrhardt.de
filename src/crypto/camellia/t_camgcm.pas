{-Test prog for CAM_GCM, we 11.2017}

program T_GCMSP;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifdef BIT16}
{$N+}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
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
    CAM_Base, CAM_GCM,
  {$endif}
  BTypes,
  Mem_Util;


const
  print: boolean = true;

{---------------------------------------------------------------------------}
procedure tsd_test;
  {-Reproduce CAM part of Tom St Denis' GCM_TV.TXT}
const
  hex32: array[1..32] of byte = ($00,$01,$02,$03,$04,$05,$06,$07,
                                 $08,$09,$0a,$0b,$0c,$0d,$0e,$0f,
                                 $10,$11,$12,$13,$14,$15,$16,$17,
                                 $18,$19,$1a,$1b,$1c,$1d,$1e,$1f);
  buf32: array[0..31] of byte = ($50,$90,$ff,$37,$ef,$4f,$16,$3f,
                                 $5b,$54,$ae,$a5,$4d,$af,$1c,$da,
                                 $c1,$12,$5c,$46,$a8,$61,$7c,$e3,
                                 $d2,$51,$57,$6b,$f5,$21,$43,$e2);


  tag32: array[0..15] of byte = ($18,$2f,$d3,$ed,$46,$3e,$1a,$6a,
                                 $61,$5f,$4e,$25,$b3,$4c,$a7,$48);


var
  err,n: integer;
  ctx: TCAM_GCMContext;
  key, tag: TCAMBlock;
  buf: array[0..63] of byte;
begin
  writeln('Test CAM part of Tom St Denis'' GCM_TV.TXT (LTC V1.18)');
  {Uppercase from HexStr}
  HexUpper := true;
  {Initial key from hex32}
  move(hex32, key, sizeof(key));
  for n:=1 to 32 do begin
    err := CAM_GCM_Init(key, 128, ctx);
    if err=0 then err := CAM_GCM_Reset_IV(@hex32, n, ctx);
    if err=0 then err := CAM_GCM_Add_AAD(@hex32,n,ctx);
    if err=0 then err := CAM_GCM_Encrypt(@hex32, @buf, n, ctx);
    if err=0 then err := CAM_GCM_Final(tag, ctx);
    if err=0 then begin
      if print then writeln(n:3,': ', HexStr(@buf,n), ', ', HexStr(@tag,16));
      {key for step n>1 is the tag of the previous step repeated}
      key := tag;
    end
    else begin
      writeln('Error ',err);
      exit;
    end;
  end;
  {compare final values}
  writeln('buf32 compares: ', compmem(@buf32, @buf, sizeof(buf32)):5);
  writeln('tag32 compares: ', compmem(@tag32, @tag, sizeof(tag32)):5);
end;

begin
  write('Test program for CAM-GCM functions');
  {$ifdef USEDLL}
    write('  [CAM_DLL V',CAM_DLL_Version,']');
  {$endif}
  writeln('   (C) 2017  W.Ehrhardt');
  writeln;
  tsd_test;
end.




