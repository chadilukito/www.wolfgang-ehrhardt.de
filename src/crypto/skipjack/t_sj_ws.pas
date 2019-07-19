{-Speed test prog for SkipJack modes, we Jul.2009}

program T_SJ_WS;

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
      SJ_Intv,
    {$else}
      SJ_Intf,
    {$endif}
  {$else}
    sj_base, sj_ctr, sj_cfb, sj_ofb, sj_cbc, sj_ecb,
  {$endif}
  BTypes, mem_util;

const
     key : array[0..09] of byte = ($11,$22,$33,$44,$55,$66,$77,$88,$99,$00);

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


  {Test vectors calculated with CryptoBench using Wei Dai's Crypto++ V5+}
  {using http://www.addario.org/files/CryptoBench%20v1.0.1.zip}
  
  ct_cbc : array[0..63] of byte = ($17,$ba,$e4,$00,$e7,$c1,$85,$58,
                                   $68,$16,$f0,$09,$a0,$05,$99,$42,
                                   $44,$81,$e1,$28,$fb,$95,$c5,$d2,
                                   $0d,$53,$22,$a1,$04,$e6,$76,$88,
                                   $ec,$c8,$91,$88,$8b,$0f,$36,$bb,
                                   $24,$98,$5e,$e7,$d9,$e5,$c5,$40,
                                   $bc,$91,$25,$3f,$23,$8e,$bd,$e7,
                                   $8d,$00,$0f,$b7,$c6,$4d,$ce,$14);

  ct_ctr : array[0..63] of byte = ($58,$a0,$ae,$43,$41,$9d,$ed,$0e,
                                   $00,$8f,$f9,$f3,$0f,$4f,$b0,$f6,
                                   $a4,$b7,$84,$69,$c5,$d8,$e4,$e7,
                                   $32,$64,$fa,$27,$69,$ce,$15,$54,
                                   $cd,$fb,$10,$83,$8b,$fc,$63,$e9,
                                   $72,$99,$d5,$05,$3c,$cf,$90,$f7,
                                   $12,$d0,$0d,$a7,$82,$e7,$7d,$5c,
                                   $36,$3e,$9e,$25,$58,$fc,$e6,$2c);

  ct_cfb : array[0..63] of byte = ($ea,$e5,$2c,$5f,$4d,$ec,$e0,$fb,
                                   $d7,$45,$5a,$05,$fe,$80,$d1,$8e,
                                   $a6,$98,$e3,$f6,$dc,$04,$bd,$10,
                                   $5c,$f7,$a4,$1f,$d8,$2a,$ce,$83,
                                   $89,$78,$33,$eb,$ee,$ea,$b2,$d9,
                                   $40,$32,$31,$3f,$3d,$c8,$9c,$f6,
                                   $bc,$ce,$97,$cd,$2a,$d6,$b1,$c2,
                                   $35,$47,$02,$d9,$e2,$05,$11,$e9);


  ct_ofb : array[0..63] of byte = ($ea,$e5,$2c,$5f,$4d,$ec,$e0,$fb,
                                   $00,$32,$7e,$57,$6c,$e7,$f8,$4f,
                                   $58,$ff,$d2,$1a,$40,$0a,$4e,$75,
                                   $dd,$53,$7a,$bb,$68,$60,$95,$3f,
                                   $cf,$34,$05,$01,$19,$b9,$7f,$58,
                                   $ff,$d9,$df,$b6,$f0,$d9,$55,$0b,
                                   $be,$3b,$4a,$33,$0b,$e3,$23,$cd,
                                   $65,$33,$96,$91,$8d,$90,$09,$85);

  ct_ecb : array[0..63] of byte = ($8b,$f1,$f0,$0c,$64,$4d,$ad,$48,
                                   $a7,$6e,$59,$05,$c7,$91,$18,$75,
                                   $13,$8d,$76,$5a,$93,$70,$fe,$09,
                                   $af,$55,$54,$db,$42,$c6,$9f,$e0,
                                   $e5,$ad,$24,$32,$c0,$de,$f7,$07,
                                   $0c,$74,$f1,$0d,$b0,$6e,$3f,$7f,
                                   $f2,$6f,$09,$7e,$fb,$32,$4f,$f1,
                                   $b1,$53,$be,$a3,$36,$c6,$be,$b5);

  ct_cts : array[0..62] of byte = ($17,$ba,$e4,$00,$e7,$c1,$85,$58,
                                   $68,$16,$f0,$09,$a0,$05,$99,$42,
                                   $44,$81,$e1,$28,$fb,$95,$c5,$d2,
                                   $0d,$53,$22,$a1,$04,$e6,$76,$88,
                                   $ec,$c8,$91,$88,$8b,$0f,$36,$bb,
                                   $24,$98,$5e,$e7,$d9,$e5,$c5,$40,
                                   $52,$a1,$3b,$2f,$83,$ca,$37,$83,
                                   $bc,$91,$25,$3f,$23,$8e,$bd);

var
  ct: array[0..63] of byte;

var
  Context: TSJContext;

const
  N: longint = 4*1000000;  {128MB}


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
  if SJ_CFB_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error CFB');
    exit;
  end;
  for i:=1 to N do begin
    if SJ_CFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if SJ_CBC_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error CBC');
    exit;
  end;
  for i:=1 to N do begin
    if SJ_CBC_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CBC');
      exit;
    end;
  end;
  if N=1 then begin
    writeln('CBC  test: ', test(@ct,@ct_cbc));
  end;
end;

{---------------------------------------------------------------------------}
procedure TestCTS;
var
  i: longint;
begin
  if SJ_CBC_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error CBC/CTS');
    exit;
  end;
  for i:=1 to N do begin
    if SJ_CBC_Encrypt(@plain, @ct, sizeof(ct_cts), context)<>0 then begin
      writeln('*** Error CBC/CTS');
      exit;
    end;
  end;
  if N=1 then begin
    write('CBC/CTS  : ');
    if compmem(@ct,@ct_cts, sizeof(ct_cts)) then writeln('OK') else writeln('Error');
  end;
end;


{---------------------------------------------------------------------------}
procedure TestECB;
var
  i: longint;
begin
  if SJ_ECB_Init(key, sizeof(key), context)<>0 then begin
    writeln('*** Error ECB');
    exit;
  end;
  for i:=1 to N do begin
    if SJ_ECB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if SJ_CTR_Init(key, sizeof(key), TSJBlock(CTR), context)<>0 then begin
    writeln('*** Error CTR');
    exit;
  end;
  for i:=1 to N do begin
    if SJ_CTR_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if SJ_OFB_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error OFB');
    exit;
  end;
  for i:=1 to N do begin
    if SJ_OFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
    s: string[10];
  {$endif}
  i: integer;
begin
  {$ifdef USEDLL}
    writeln('Test program for SJ_DLL V',SJ_DLL_Version,'   (C) 2009  W.Ehrhardt');
  {$else}
    writeln('Test program for SkipJack modes    (C) 2009  W.Ehrhardt');
  {$endif}
  s := paramstr(1);
  SJ_SetFastInit(true);
  for i:=1 to length(s) do s[i] := upcase(s[i]);
  if s='TEST' then begin
    N := 1;
    TestCBC;
    TestCFB;
    TestCTR;
    TestECB;
    TestOFB;
    TestCTS;
  end
  else if s='CBC'  then TestCBC
  else if s='CFB'  then TestCFB
  else if s='CTR'  then TestCTR
  else if s='ECB'  then TestECB
  else if s='OFB'  then TestOFB
  else begin
    writeln('Usage: T_SJ_WS  [ TEST | CBC | CFB | CTR | ECB | OFB ]');
    halt;
  end;
end.
