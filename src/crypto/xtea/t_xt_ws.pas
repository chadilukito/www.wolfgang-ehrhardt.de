{-Speed test prog for XTEA modes, we Jan.2005}

program T_XT_WS;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifdef J_OPT}
  {$J+}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  {$ifdef USEDLL}
    {$ifdef VirtualPascal}
      XT_Intv,
    {$else}
      XT_Intf,
    {$endif}
  {$else}
    xt_base, xt_ctr, xt_cfb, xt_ofb, xt_cbc, xt_ecb,
  {$endif}
  BTypes, mem_util;

const
  key128 : array[0..15] of byte = ($78,$56,$34,$12,$f0,$cd,$cb,$9a,
                                   $48,$37,$26,$15,$c0,$bf,$ae,$9d);

      IV : array[0..07] of byte = ($00,$01,$02,$03,$04,$05,$06,$07);

     CTR : array[0..07] of byte = ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7);

  plain  : array[0..63] of byte = ($01,$02,$03,$04,$05,$06,$07,$08,
                                   $11,$12,$13,$14,$15,$16,$17,$18,
                                   $21,$22,$23,$24,$25,$26,$27,$28,
                                   $31,$32,$33,$34,$35,$36,$37,$38,
                                   $41,$42,$43,$44,$45,$46,$47,$48,
                                   $51,$52,$53,$54,$55,$56,$57,$58,
                                   $61,$62,$63,$64,$65,$66,$67,$68,
                                   $71,$72,$73,$74,$75,$76,$77,$78);

{Cipher text vectors calculated with LTC 1.00, t_xt.c and xtea_we.c}

  ct_cbc: array[0.. 63] of byte = ($13,$31,$dc,$0a,$96,$4c,$77,$7f,
                                   $38,$b4,$11,$43,$a3,$7e,$3f,$22,
                                   $08,$9e,$e8,$9a,$67,$dc,$63,$e2,
                                   $88,$8b,$25,$17,$7e,$f0,$f4,$5c,
                                   $3c,$49,$d6,$73,$b7,$65,$38,$21,
                                   $c8,$74,$7f,$45,$04,$37,$2e,$98,
                                   $16,$56,$ad,$70,$b2,$9a,$d5,$6c,
                                   $5a,$1e,$1f,$be,$e0,$7d,$c1,$99);

  ct_ctr: array[0.. 63] of byte = ($21,$a3,$e4,$bf,$7f,$12,$aa,$32,
                                   $b8,$75,$62,$18,$42,$62,$9f,$ab,
                                   $94,$72,$7d,$8a,$00,$d4,$61,$e5,
                                   $55,$1e,$5b,$db,$6c,$03,$4b,$b8,
                                   $fc,$5f,$0a,$ea,$f8,$b2,$31,$53,
                                   $f0,$9c,$cd,$e9,$de,$56,$b5,$f5,
                                   $a2,$22,$0b,$92,$8a,$7c,$a3,$87,
                                   $06,$5e,$bf,$cf,$ff,$b2,$19,$3c);

  ct_cfb: array[0.. 63] of byte = ($61,$e4,$61,$62,$93,$5e,$c2,$38,
                                   $1a,$82,$a5,$9a,$51,$8d,$66,$b1,
                                   $40,$3c,$2a,$a8,$87,$ef,$dd,$59,
                                   $a7,$e9,$07,$6c,$71,$b0,$2a,$b8,
                                   $a8,$d7,$77,$ac,$39,$06,$d5,$fe,
                                   $ff,$a1,$74,$e8,$37,$a5,$21,$90,
                                   $c5,$22,$19,$81,$19,$73,$75,$c0,
                                   $ef,$b7,$85,$6c,$1c,$b7,$a1,$f3);

  ct_ofb: array[0.. 63] of byte = ($61,$e4,$61,$62,$93,$5e,$c2,$38,
                                   $c9,$d5,$1d,$1c,$d1,$d8,$f3,$21,
                                   $dc,$91,$89,$a5,$f4,$00,$2b,$26,
                                   $9d,$ce,$33,$2a,$bb,$9b,$38,$46,
                                   $b9,$a2,$dc,$8f,$b6,$0c,$8c,$6c,
                                   $66,$dc,$0a,$4d,$ad,$04,$a1,$26,
                                   $c8,$32,$af,$55,$49,$70,$3c,$41,
                                   $40,$1b,$74,$7b,$e3,$d4,$93,$ae);

  ct_ecb: array[0.. 63] of byte = ($58,$70,$8a,$ac,$76,$a3,$ce,$66,
                                   $86,$38,$a9,$24,$b1,$b8,$e5,$96,
                                   $b1,$ca,$8d,$e0,$e0,$e7,$e3,$58,
                                   $d0,$ca,$86,$ac,$5d,$12,$f8,$9b,
                                   $c0,$31,$6c,$b6,$02,$80,$0e,$01,
                                   $33,$0e,$33,$d1,$04,$66,$89,$53,
                                   $88,$35,$1b,$b0,$ef,$9b,$70,$f2,
                                   $76,$a6,$bb,$dc,$de,$05,$a7,$b7);

var
  ct: array[0..63] of byte;

var
  Context: TXTContext;

const
  N : longint = 4*1000000;  {256MB}


{---------------------------------------------------------------------------}
function test(px,py: pointer): Str255;
begin
  if compmem(px,py,64) then test := 'OK' else test := 'Error';
end;


{---------------------------------------------------------------------------}
procedure TestCFB;
var
  i: longint;
begin
  if XT_CFB_Init(key128, sizeof(key128), TXTBlock(IV), context)<>0 then begin
    writeln('*** Error CFB');
    exit;
  end;
  for i:=1 to N do begin
    if XT_CFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CFB');
      exit;
    end;
  end;
  if N=1 then begin
    writeln('CFB  test: ', test(@ct,@ct_cfb));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestCBC;
var
  i: longint;
begin
  if XT_CBC_Init(key128, sizeof(key128), TXTBlock(IV), context)<>0 then begin
    writeln('*** Error CBC');
    exit;
  end;
  for i:=1 to N do begin
    if XT_CBC_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CBC');
      exit;
    end;
  end;
  if N=1 then begin
    writeln('CBC  test: ', test(@ct,@ct_cbc));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestECB;
var
  i: longint;
begin
  if XT_ECB_Init(key128, sizeof(key128), context)<>0 then begin
    writeln('*** Error ECB');
    exit;
  end;
  for i:=1 to N do begin
    if XT_ECB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error ECB');
      exit;
    end;
  end;
  if N=1 then begin
    writeln('ECB  test: ', test(@ct,@ct_ECB));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestCTR;
var
  i: longint;
begin
  if XT_CTR_Init(key128, sizeof(key128), TXTBlock(CTR), context)<>0 then begin
    writeln('*** Error CTR');
    exit;
  end;
  for i:=1 to N do begin
    if XT_CTR_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CTR');
      exit;
    end;
  end;
  if N=1 then begin
    writeln('CTR  test: ', test(@ct,@ct_ctr));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestOFB;
var
  i: longint;
begin
  if XT_OFB_Init(key128, sizeof(key128), TXTBlock(IV), context)<>0 then begin
    writeln('*** Error OFB');
    exit;
  end;
  for i:=1 to N do begin
    if XT_OFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error OFB');
      exit;
    end;
  end;
  if N=1 then begin
    writeln('OFB  test: ', test(@ct,@ct_ofb));
  end;
end;


var
  {$ifdef D12Plus}
    s: string;
  {$else}
    s: string[20];
  {$endif}
  i: integer;
begin
  {$ifdef USEDLL}
    writeln('Test program for XT_DLL V',XT_DLL_Version,'   (C) 2005-2009  W.Ehrhardt');
  {$else}
    writeln('Test program for XTEA modes    (C) 2005-2009  W.Ehrhardt');
  {$endif}
  s := paramstr(1);
  XT_SetFastInit(true);
  for i:=1 to length(s) do s[i] := upcase(s[i]);
  if s='TEST' then begin
    N := 1;
    TestCBC;
    TestCFB;
    TestCTR;
    TestECB;
    TestOFB;
  end
  else if s='CBC'  then TestCBC
  else if s='CFB'  then TestCFB
  else if s='CTR'  then TestCTR
  else if s='ECB'  then TestECB
  else if s='OFB'  then TestOFB
  else begin
    writeln('Usage: T_XT_WS  [ TEST | CBC | CFB | CTR | ECB | OFB ]');
    halt;
  end;
end.
