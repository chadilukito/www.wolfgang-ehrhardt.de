{-Speed test prog for Anubis modes, (c) we Aug.2008}

program T_ANU_WS;

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
      ANU_Intv,
    {$else}
      ANU_Intf,
    {$endif}
  {$else}
    anu_base,anu_ctr,anu_cfb,anu_ofb,anu_cbc,
    anu_ecb,anu_omac,anu_eax,
  {$endif}
  BTypes,mem_util;

const
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);

      IV : TANUBlock =            ($00,$01,$02,$03,$04,$05,$06,$07,
                                   $08,$09,$0a,$0b,$0c,$0d,$0e,$0f);

     CTR : TANUBlock =            ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7,
                                   $f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

  plain  : array[0..63] of byte = ($6b,$c1,$be,$e2,$2e,$40,$9f,$96,
                                   $e9,$3d,$7e,$11,$73,$93,$17,$2a,
                                   $ae,$2d,$8a,$57,$1e,$03,$ac,$9c,
                                   $9e,$b7,$6f,$ac,$45,$af,$8e,$51,
                                   $30,$c8,$1c,$46,$a3,$5c,$e4,$11,
                                   $e5,$fb,$c1,$19,$1a,$0a,$52,$ef,
                                   $f6,$9f,$24,$45,$df,$4f,$9b,$17,
                                   $ad,$2b,$41,$7b,$e6,$6c,$37,$10);

  ct_cbc : array[0..63] of byte = ($ef,$24,$33,$17,$81,$27,$9b,$58,
                                   $00,$3f,$4d,$29,$e3,$f0,$a5,$83,
                                   $00,$4f,$2a,$54,$53,$76,$c8,$5a,
                                   $c5,$3f,$30,$b3,$0a,$95,$3f,$6c,
                                   $91,$7f,$de,$54,$c6,$b8,$90,$55,
                                   $a6,$5a,$20,$18,$18,$78,$5b,$8e,
                                   $27,$3a,$f7,$e0,$fb,$2f,$ac,$5d,
                                   $0f,$2c,$4a,$34,$c5,$dc,$71,$18);

  ct_cfb : array[0..63] of byte = ($02,$4f,$81,$75,$30,$56,$dc,$a4,
                                   $49,$10,$9d,$9e,$38,$43,$f2,$4e,
                                   $74,$54,$c2,$c5,$24,$d1,$c6,$29,
                                   $35,$54,$1d,$d2,$7a,$58,$4c,$61,
                                   $12,$6c,$e5,$51,$97,$89,$12,$07,
                                   $0f,$f6,$cf,$14,$f8,$e7,$fe,$68,
                                   $4d,$f2,$ce,$8f,$1d,$fc,$7c,$d2,
                                   $37,$31,$e6,$07,$cf,$ce,$f5,$bd);

  ct_ctr : array[0..63] of byte = ($44,$b9,$7c,$f7,$24,$50,$e7,$27,
                                   $62,$7d,$d5,$06,$9f,$78,$86,$b0,
                                   $34,$87,$6c,$c6,$25,$ab,$4b,$2a,
                                   $17,$cb,$d2,$6d,$8f,$42,$06,$c2,
                                   $18,$e3,$92,$7b,$95,$29,$55,$3b,
                                   $a9,$94,$8a,$a0,$27,$a2,$bb,$5f,
                                   $1f,$34,$1f,$77,$bf,$14,$26,$10,
                                   $7c,$e5,$47,$49,$81,$84,$75,$29);

  ct_ofb : array[0..63] of byte = ($02,$4f,$81,$75,$30,$56,$dc,$a4,
                                   $49,$10,$9d,$9e,$38,$43,$f2,$4e,
                                   $02,$93,$7b,$0c,$f3,$dc,$fc,$e3,
                                   $62,$1c,$33,$92,$20,$57,$d7,$71,
                                   $5e,$d5,$05,$00,$73,$f8,$a8,$36,
                                   $35,$fe,$66,$e3,$61,$42,$25,$81,
                                   $68,$f1,$d7,$a8,$51,$f2,$8c,$dc,
                                   $6c,$e6,$4a,$17,$da,$b4,$4c,$f7);

  ct_ecb : array[0..63] of byte = ($da,$e1,$f2,$4d,$bc,$63,$7a,$4d,
                                   $c4,$e3,$96,$50,$35,$4c,$7d,$f2,
                                   $36,$d5,$a6,$35,$b7,$a8,$32,$99,
                                   $d3,$cb,$6b,$74,$89,$88,$c2,$72,
                                   $67,$0f,$19,$71,$df,$d8,$d5,$8c,
                                   $0a,$20,$04,$a0,$a6,$24,$78,$3e,
                                   $0c,$97,$88,$18,$98,$f7,$6f,$e0,
                                   $f7,$5d,$35,$57,$fa,$9e,$d6,$d2);

  omactag: TANUBlock = ($49,$53,$ce,$ee,$59,$73,$11,$70,$85,$79,$8b,$6b,$21,$e9,$57,$6f);

var
  ct: array[0..63] of byte;

var
  Context: TANUContext;

const
  N : longint = 8*1000000;  {512MB}


{---------------------------------------------------------------------------}
function test(px,py: pointer): str255;
begin
  if compmem(px,py,64) then test := 'OK' else test := 'Error';
end;


{---------------------------------------------------------------------------}
procedure TestCFB;
var
  i: longint;
begin
  if ANU_CFB_Init(key128, 128, IV, context)<>0 then begin
    writeln('*** Error CFB');
    exit;
  end;
  for i:=1 to N do begin
    if ANU_CFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if ANU_CBC_Init_Encr(key128, 128, IV, context)<>0 then begin
    writeln('*** Error CBC');
    exit;
  end;
  for i:=1 to N do begin
    if ANU_CBC_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if ANU_ECB_Init_Encr(key128, 128, context)<>0 then begin
    writeln('*** Error ECB');
    exit;
  end;
  for i:=1 to N do begin
    if ANU_ECB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if ANU_CTR_Init(key128, 128, CTR, context)<>0 then begin
    writeln('*** Error CTR');
    exit;
  end;
  for i:=1 to N do begin
    if ANU_CTR_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if ANU_OFB_Init(key128, 128, IV, context)<>0 then begin
    writeln('*** Error OFB');
    exit;
  end;
  for i:=1 to N do begin
    if ANU_OFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error OFB');
      exit;
    end;
  end;
  if N=1 then begin
    writeln('OFB  test: ', test(@ct,@ct_ofb));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestOMAC;
var
  i: longint;
  tag: TANUBlock;
begin
  if ANU_OMAC_Init(key128, 128, context)<>0 then begin
    writeln('*** Error OMAC Init');
    exit;
  end;
  for i:=1 to N do begin
    if ANU_OMAC_Update(@plain, 64, context)<>0 then begin
      writeln('*** Error OMAC update');
      exit;
    end;
  end;
  ANU_OMAC_Final(tag, context);
  if N=1 then begin
    write('OMAC test: ');
    if compmem(@tag, @omactag, sizeof(omactag)) then writeln('OK') else writeln('Error');
 end;
end;


{---------------------------------------------------------------------------}
procedure TestEAX;
  {-Anubis part of Tom St Denis' EAX_TV.TXT}
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
  {Initial key from hex32}
  move(hex32, key, sizeof(key));
  for n:=0 to 32 do begin
    err := ANU_EAX_Init(key, 128, hex32, n, ctx);
    if err=0 then err := ANU_EAX_Provide_Header(@hex32, n, ctx);
    if err=0 then err := ANU_EAX_Encrypt(@hex32, @buf, n, ctx);
    if err=0 then begin
      ANU_EAX_Final(tag, ctx);
      if n<32 then key := tag;
    end
    else begin
      writeln('*** Enc EAX error');
      exit;
    end;
  end;
  if not compmem(@buf32, @buf, sizeof(buf32)) then begin
    writeln('*** Enc EAX diff buf');
    exit;
  end;
  if not compmem(@tag32, @tag, sizeof(tag32)) then begin
    writeln('*** Enc EAX diff tag');
    exit;
  end;
  n := 32;
  err := ANU_EAX_Init(key, 128, hex32, n, ctx);
  if err=0 then err := ANU_EAX_Provide_Header(@hex32, n, ctx);
  if err=0 then err := ANU_EAX_Decrypt(@buf32, @buf, n, ctx);
  if err=0 then ANU_EAX_Final(tag, ctx)
  else begin
    writeln('*** Dec EAX error');
    exit;
  end;
  if not compmem(@hex32, @buf, sizeof(buf32)) then begin
    writeln('*** Dec EAX diff buf');
    exit;
  end;
  if not compmem(@tag32, @tag, sizeof(tag32)) then begin
    writeln('*** Dec EAX diff tag');
    exit;
  end;
  write('EAX  test: OK');
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
    writeln('Test program for ANU_DLL V',ANU_DLL_Version,'   (C) 2008-2009  W.Ehrhardt');
  {$else}
    writeln('Test program for Anubis functions    (C) 2008-2009  W.Ehrhardt');
  {$endif}
  ANU_SetFastInit(true);
  s := paramstr(1);
  for i:=1 to length(s) do s[i] := upcase(s[i]);
  if s='TEST' then begin
    N := 1;
    TestCBC;
    TestCFB;
    TestCTR;
    TestECB;
    TestOFB;
    TestOMAC;
    TestEAX;
    writeln;
  end
  else if s='CBC'  then TestCBC
  else if s='CFB'  then TestCFB
  else if s='CTR'  then TestCTR
  else if s='ECB'  then TestECB
  else if s='OFB'  then TestOFB
  else if s='OMAC' then TestOMAC
  else begin
    writeln('Usage: T_ANU_WS  [ TEST | CBC | CFB | CTR | ECB | OFB | OMAC ]');
    halt;
  end;
end.
