{-Speed test prog for SHACAL-2 modes, we 2006}

program T_SC_WS;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifdef J_OPT}
  {$J+}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  {$ifdef USEDLL}
    {$ifdef VirtualPascal}
      SC_Intv,
    {$else}
      SC_Intf,
    {$endif}
  {$else}
    SC_base, SC_ctr, SC_cfb, SC_ofb, SC_cbc, SC_ecb,
  {$endif}
  BTypes,mem_util;

const
  key   : array[0.. 63] of byte = ($32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32);
  IV    : array[0.. 31] of byte = ($42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42);

  plain : array[0..127] of char8= '1111111111111111111111111111111122222222222222222222222222222222'+
                                  '3333333333333333333333333333333344444444444444444444444444444444';

  {Test vectors calculated with StreamSec Tools 3 / Cipherdemo}

  ct_cbc: array[0..127] of byte = ($69,$aa,$39,$1b,$15,$e5,$97,$2b,
                                   $f6,$c2,$d4,$b1,$e3,$48,$53,$52,
                                   $c8,$c8,$b1,$2a,$12,$48,$4b,$78,
                                   $a3,$2c,$7e,$57,$b0,$8f,$1e,$ce,
                                   $bc,$8e,$90,$13,$99,$25,$41,$fb,
                                   $43,$47,$f1,$a9,$c8,$80,$0f,$81,
                                   $bd,$d9,$54,$2a,$c9,$a9,$80,$d7,
                                   $cc,$2b,$5f,$c8,$48,$51,$a1,$20,
                                   $64,$18,$97,$80,$b8,$51,$92,$19,
                                   $6c,$28,$d1,$d3,$a8,$6d,$ce,$95,
                                   $b4,$73,$12,$9e,$fb,$43,$b7,$87,
                                   $a0,$0c,$c4,$a5,$60,$56,$79,$08,
                                   $93,$7c,$23,$87,$a3,$14,$6b,$a1,
                                   $fd,$08,$8e,$9a,$aa,$7f,$04,$b4,
                                   $2f,$e4,$c3,$70,$cc,$a8,$d3,$f9,
                                   $40,$1d,$01,$61,$f8,$e3,$26,$4E);


  ct_ctr: array[0..127] of byte = ($45,$9b,$ff,$59,$c9,$31,$8b,$08,
                                   $ef,$b9,$d6,$62,$9f,$bc,$7a,$6a,
                                   $1b,$b3,$64,$f1,$ce,$c2,$b9,$22,
                                   $17,$10,$c1,$48,$f1,$ea,$3a,$66,
                                   $22,$4d,$3f,$52,$1a,$e7,$2b,$52,
                                   $07,$e4,$c7,$96,$c6,$cb,$7b,$3f,
                                   $05,$49,$ca,$d0,$58,$02,$d8,$4a,
                                   $7c,$3e,$fe,$c5,$a6,$00,$d6,$72,
                                   $6d,$80,$91,$60,$25,$6b,$96,$3b,
                                   $ae,$ee,$2c,$82,$cb,$ad,$c6,$2b,
                                   $1a,$ca,$ac,$9f,$be,$e7,$ce,$1a,
                                   $6b,$bf,$db,$d6,$3b,$8b,$ae,$97,
                                   $71,$a4,$b2,$8f,$05,$58,$7e,$e0,
                                   $6b,$30,$37,$70,$88,$36,$4a,$c4,
                                   $54,$b3,$b3,$00,$02,$9f,$ff,$83,
                                   $05,$e6,$40,$59,$49,$d6,$24,$ec);


  ct_ecb: array[0..127] of byte = ($27,$ce,$80,$46,$34,$20,$d6,$dc,
                                   $d8,$e0,$d0,$0c,$d4,$a1,$f0,$f3,
                                   $62,$37,$1d,$c7,$6f,$f2,$9d,$fd,
                                   $41,$c6,$9b,$3b,$ed,$91,$00,$db,
                                   $8b,$ac,$47,$9f,$3a,$92,$df,$71,
                                   $f9,$73,$aa,$45,$7e,$19,$d7,$5f,
                                   $b0,$f1,$a0,$fe,$68,$ff,$44,$0a,
                                   $86,$15,$47,$21,$bc,$c3,$45,$d4,
                                   $de,$c1,$cc,$59,$42,$75,$07,$9b,
                                   $14,$7d,$11,$f9,$ca,$87,$b7,$6f,
                                   $3f,$f0,$84,$e3,$4f,$d1,$20,$29,
                                   $32,$4d,$4c,$bb,$ca,$09,$ad,$82,
                                   $ad,$ff,$b7,$f7,$2a,$e5,$54,$6c,
                                   $9e,$88,$02,$49,$6d,$62,$c9,$66,
                                   $a1,$8a,$43,$99,$b7,$bc,$f9,$82,
                                   $50,$0f,$93,$cf,$c5,$ad,$30,$60);


  ct_cfb: array[0..127] of byte = ($45,$9b,$ff,$59,$c9,$31,$8b,$08,
                                   $ef,$b9,$d6,$62,$9f,$bc,$7a,$6a,
                                   $1b,$b3,$64,$f1,$ce,$c2,$b9,$22,
                                   $17,$10,$c1,$48,$f1,$ea,$3a,$66,
                                   $4e,$b3,$1a,$41,$5d,$4c,$0b,$2b,
                                   $ef,$40,$1c,$36,$c0,$90,$22,$8b,
                                   $c9,$5a,$fe,$00,$5a,$1c,$fa,$88,
                                   $99,$b6,$ec,$a0,$35,$08,$37,$03,
                                   $dc,$79,$8b,$a6,$03,$6a,$1a,$7c,
                                   $64,$3e,$71,$f8,$69,$14,$b7,$aa,
                                   $b9,$a6,$d7,$d6,$dd,$08,$25,$9e,
                                   $b0,$2d,$7d,$c9,$6e,$0d,$d3,$79,
                                   $df,$d0,$70,$97,$b4,$10,$c6,$10,
                                   $fe,$9a,$7f,$c0,$eb,$2e,$11,$ff,
                                   $32,$79,$cd,$e7,$d5,$dc,$84,$22,
                                   $50,$ba,$4f,$e9,$06,$6f,$38,$07);

  ct_ofb: array[0..127] of byte = ($45,$9b,$ff,$59,$c9,$31,$8b,$08,
                                   $ef,$b9,$d6,$62,$9f,$bc,$7a,$6a,
                                   $1b,$b3,$64,$f1,$ce,$c2,$b9,$22,
                                   $17,$10,$c1,$48,$f1,$ea,$3a,$66,
                                   $3b,$d2,$81,$54,$29,$4f,$43,$2b,
                                   $e7,$6f,$7a,$85,$b2,$25,$60,$4d,
                                   $06,$e2,$d5,$77,$8b,$47,$44,$40,
                                   $2f,$a0,$e8,$58,$29,$57,$12,$17,
                                   $a6,$a5,$fc,$ad,$c6,$63,$ed,$75,
                                   $fc,$98,$ae,$d0,$e9,$cb,$7d,$aa,
                                   $27,$9c,$3c,$d4,$e7,$27,$c8,$13,
                                   $0a,$26,$69,$63,$6c,$a2,$58,$65,
                                   $a7,$55,$8b,$15,$3a,$b7,$62,$6a,
                                   $62,$65,$c2,$12,$9b,$96,$73,$b2,
                                   $6d,$fc,$c8,$5c,$4d,$ad,$6f,$44,
                                   $51,$a0,$a1,$fb,$74,$f0,$97,$6c);

var
  ct: array[0..127] of byte;

var
  Context: TSCContext;

const
  N : longint = 4*1000000;  {512MB}


{---------------------------------------------------------------------------}
function test(px,py: pointer): Str255;
begin
  if compmem(px,py,128) then test := 'OK' else test := 'Error';
end;



{---------------------------------------------------------------------------}
procedure TestCBC;
var
  i: longint;
begin
  if SC_CBC_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error CBC');
    exit;
  end;
  for i:=1 to N do begin
    if SC_CBC_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if SC_ECB_Init(key, sizeof(key), context)<>0 then begin
    writeln('*** Error ECB');
    exit;
  end;
  for i:=1 to N do begin
    if SC_ECB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if SC_CTR_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error CTR');
    exit;
  end;
  for i:=1 to N do begin
    if SC_CTR_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CTR');
      exit;
    end;
  end;
  if N=1 then begin
    writeln('CTR  test: ', test(@ct,@ct_ctr));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestCFB;
var
  i: longint;
begin
  if SC_CFB_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error CFB');
    exit;
  end;
  for i:=1 to N do begin
    if SC_CFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CFB');
      exit;
    end;
  end;
  if N=1 then begin
    writeln('CFB  test: ', test(@ct,@ct_cfb));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestOFB;
var
  i: longint;
begin
  if SC_OFB_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error OFB');
    exit;
  end;
  for i:=1 to N do begin
    if SC_OFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
    writeln('Test program for SC_DLL V',SC_DLL_Version,'   (C) 2006-2009  W.Ehrhardt');
  {$else}
    writeln('Test program for SHACAL-2 modes    (C) 2006-2009  W.Ehrhardt');
  {$endif}
  s := paramstr(1);
  SC_SetFastInit(true);
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
  else if s='ECB'  then TestECB
  else if s='OFB'  then TestOFB
  else if s='CTR'  then TestCTR
  else begin
    writeln('Usage: T_SC_WS  [ TEST | CBC | CFB | CTR | ECB | OFB ]');
    halt;
  end;
end.
