{-Speed test prog for SEED modes, we 06.2007}

program T_SEA_WS;

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
      SEA_Intv,
    {$else}
      SEA_Intf,
    {$endif}
  {$else}
    SEA_base, SEA_ctr, SEA_cfb, SEA_ofb, SEA_cbc, SEA_ecb, SEA_OMAC, SEA_EAX,
  {$endif}
  BTypes, mem_util;

const
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);

      IV : array[0..15] of byte = ($00,$01,$02,$03,$04,$05,$06,$07,
                                   $08,$09,$0a,$0b,$0c,$0d,$0e,$0f);

     CTR : array[0..15] of byte = ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7,
                                   $f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

  plain  : array[0..63] of byte = ($6b,$c1,$be,$e2,$2e,$40,$9f,$96,
                                   $e9,$3d,$7e,$11,$73,$93,$17,$2a,
                                   $ae,$2d,$8a,$57,$1e,$03,$ac,$9c,
                                   $9e,$b7,$6f,$ac,$45,$af,$8e,$51,
                                   $30,$c8,$1c,$46,$a3,$5c,$e4,$11,
                                   $e5,$fb,$c1,$19,$1a,$0a,$52,$ef,
                                   $f6,$9f,$24,$45,$df,$4f,$9b,$17,
                                   $ad,$2b,$41,$7b,$e6,$6c,$37,$10);

  ct_cbc : array[0..63] of byte = ($34,$54,$9c,$b0,$c3,$4a,$67,$af,
                                   $d1,$a6,$18,$43,$e7,$24,$a6,$36,
                                   $5b,$e2,$ea,$9a,$52,$1f,$fe,$ba,
                                   $11,$f8,$13,$42,$0d,$25,$3a,$7c,
                                   $2b,$d6,$1b,$33,$04,$ee,$5d,$6a,
                                   $dc,$72,$9b,$aa,$61,$8f,$56,$22,
                                   $5a,$38,$6d,$95,$21,$37,$c0,$b8,
                                   $1d,$32,$5b,$be,$ab,$17,$86,$29);

  ct_cfb : array[0..63] of byte = ($9c,$64,$15,$48,$a8,$db,$7e,$88,
                                   $28,$ed,$45,$ab,$e1,$e5,$b6,$4e,
                                   $f9,$75,$b9,$cb,$a7,$de,$27,$28,
                                   $e6,$7d,$21,$48,$0b,$bc,$32,$cc,
                                   $61,$3e,$aa,$6d,$e2,$e4,$b2,$80,
                                   $c0,$ee,$51,$42,$98,$0a,$fe,$99,
                                   $b4,$2e,$e2,$42,$2f,$a6,$48,$07,
                                   $27,$25,$4a,$bb,$00,$cb,$e2,$e3);

  ct_ctr : array[0..63] of byte = ($8f,$a4,$8f,$2f,$0e,$74,$b5,$d5,
                                   $90,$55,$ad,$1d,$a6,$5a,$4e,$29,
                                   $3c,$c0,$39,$30,$81,$61,$fb,$1f,
                                   $3b,$64,$92,$0d,$0e,$fe,$e2,$46,
                                   $a1,$61,$4d,$63,$96,$a3,$ab,$25,
                                   $9e,$eb,$68,$96,$fb,$51,$aa,$27,
                                   $a6,$5e,$87,$35,$00,$9f,$25,$7b,
                                   $04,$d3,$82,$3f,$97,$bd,$02,$7e);

  ct_ofb : array[0..63] of byte = ($9c,$64,$15,$48,$a8,$db,$7e,$88,
                                   $28,$ed,$45,$ab,$e1,$e5,$b6,$4e,
                                   $8f,$d3,$a4,$e2,$70,$d8,$c2,$af,
                                   $de,$9d,$7e,$fd,$33,$0c,$09,$4b,
                                   $00,$41,$25,$c0,$c4,$45,$eb,$45,
                                   $26,$95,$63,$29,$a6,$11,$bd,$8a,
                                   $4f,$98,$47,$dd,$51,$88,$83,$1a,
                                   $a1,$ce,$cb,$8b,$e6,$33,$de,$bd);

  ct_ecb : array[0..63] of byte = ($ae,$30,$ad,$b2,$3d,$70,$8b,$63,
                                   $d4,$9e,$51,$61,$d7,$44,$44,$43,
                                   $0b,$0c,$02,$90,$82,$4a,$7f,$40,
                                   $87,$38,$5b,$b6,$85,$63,$8a,$93,
                                   $19,$e4,$68,$10,$1d,$8e,$50,$1c,
                                   $fb,$48,$bd,$01,$02,$2f,$57,$56,
                                   $b5,$ed,$6b,$1c,$28,$26,$77,$05,
                                   $74,$1e,$a5,$0c,$cf,$71,$28,$be);

var
  ct: array[0..63] of byte;

var
  Context: TSEAContext;

const
  Loops : longint = 8*1000000;  {512MB}


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
  if SEA_CFB_Init(key128, 8*sizeof(key128), TSEABlock(IV), context)<>0 then begin
    writeln('*** Error CFB');
    exit;
  end;
  for i:=1 to Loops do begin
    if SEA_CFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CFB');
      exit;
    end;
  end;
  if Loops=1 then begin
    writeln('CFB  test: ', test(@ct,@ct_cfb));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestCBC;
var
  i: longint;
begin
  if SEA_CBC_Init(key128, 8*sizeof(key128), TSEABlock(IV), context)<>0 then begin
    writeln('*** Error CBC');
    exit;
  end;
  for i:=1 to Loops do begin
    if SEA_CBC_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CBC');
      exit;
    end;
  end;
  if Loops=1 then begin
    writeln('CBC  test: ', test(@ct,@ct_cbc));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestECB;
var
  i: longint;
begin
  if SEA_ECB_Init(key128, 8*sizeof(key128), context)<>0 then begin
    writeln('*** Error ECB');
    exit;
  end;
  for i:=1 to Loops do begin
    if SEA_ECB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error ECB');
      exit;
    end;
  end;
  if Loops=1 then begin
    writeln('ECB  test: ', test(@ct,@ct_ECB));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestCTR;
var
  i: longint;
begin
  if SEA_CTR_Init(key128, 8*sizeof(key128), TSEABlock(CTR), context)<>0 then begin
    writeln('*** Error CTR');
    exit;
  end;
  for i:=1 to Loops do begin
    if SEA_CTR_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CTR');
      exit;
    end;
  end;
  if Loops=1 then begin
    writeln('CTR  test: ', test(@ct,@ct_ctr));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestOFB;
var
  i: longint;
begin
  if SEA_OFB_Init(key128, 8*sizeof(key128), TSEABlock(IV), context)<>0 then begin
    writeln('*** Error OFB');
    exit;
  end;
  for i:=1 to Loops do begin
    if SEA_OFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error OFB');
      exit;
    end;
  end;
  if Loops=1 then begin
    writeln('OFB  test: ', test(@ct,@ct_ofb));
  end;
end;



{---------------------------------------------------------------------------}
procedure TestOMAC;
var
  i: longint;
  tag: TSEABlock;
const
  tsdtag: TSEABlock = ($d2,$20,$37,$82,$4a,$61,$0c,$5d,
                       $46,$31,$9a,$65,$0c,$bf,$6c,$e0);
begin
  if SEA_OMAC_Init(key128, 128, context)<>0 then begin
    writeln('*** Error OMAC Init');
    exit;
  end;
  for i:=1 to Loops do begin
    if SEA_OMAC_Update(@plain, 64, context)<>0 then begin
      writeln('*** Error OMAC update');
      exit;
    end;
  end;
  SEA_OMAC_Final(tag, context);
  if Loops=1 then begin
    write('OMAC test: ');
    if compmem(@tsdtag, @tag, sizeof(tag)) then writeln('OK') else writeln('Error');
 end;
end;


{---------------------------------------------------------------------------}
procedure TestEAX;
  {-SEED part of Tom St Denis' EAX_TV.TXT}
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
  {Initial key from hex32}
  move(hex32, key, sizeof(key));
  for n:=0 to 32 do begin
    err := SEA_EAX_Init(key, 128, hex32, n, ctx);
    if err=0 then err := SEA_EAX_Provide_Header(@hex32,n,ctx);
    if err=0 then err := SEA_EAX_Encrypt(@hex32, @buf, n, ctx);
    if err=0 then begin
      SEA_EAX_Final(tag, ctx);
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
  err := SEA_EAX_Init(key, 128, hex32, n, ctx);
  if err=0 then err := SEA_EAX_Provide_Header(@hex32,n,ctx);
  if err=0 then err := SEA_EAX_Decrypt(@buf32, @buf, n, ctx);
  if err=0 then SEA_EAX_Final(tag, ctx)
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
    writeln('Test program for SEA_DLL V',SEA_DLL_Version,'   (C) 2007-2010  W.Ehrhardt');
  {$else}
    writeln('Test program for SEED modes    (C) 2007-2010  W.Ehrhardt');
  {$endif}
  s := paramstr(1);
  SEA_SetFastInit(true);
  for i:=1 to length(s) do s[i] := upcase(s[i]);
  if s='TEST' then begin
    Loops := 1;
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
    writeln('Usage: T_SEA_WS  [ TEST | CBC | CFB | CTR | ECB | OFB | OMAC]');
    halt;
  end;
end.
