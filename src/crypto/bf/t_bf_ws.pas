{-Speed test prog for Blowfish modes, we 2005}

program T_BF_WS;

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
      BF_Intv,
    {$else}
      BF_Intf,
    {$endif}
  {$else}
    BF_base, BF_ctr, BF_cfb, BF_ofb, BF_cbc, BF_ecb, BF_omac, BF_eax,
  {$endif}
  BTypes, mem_util;

const
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);

      IV : array[0..07] of byte = ($00,$01,$02,$03,$04,$05,$06,$07);

     CTR : array[0..07] of byte = ($f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

  plain  : array[0..63] of char8= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  ct_cbc : array[0..63] of byte = ($85,$5c,$44,$94,$53,$b4,$c1,$c3,
                                   $2e,$9d,$1a,$75,$bc,$dc,$86,$d3,
                                   $7e,$ea,$41,$da,$e9,$c1,$96,$bd,
                                   $8e,$e6,$f2,$0c,$18,$56,$e1,$60,
                                   $86,$bb,$28,$0d,$c1,$31,$39,$1c,
                                   $2f,$34,$ae,$ed,$02,$a9,$d7,$32,
                                   $4e,$63,$03,$91,$af,$14,$51,$0e,
                                   $26,$11,$bc,$f8,$33,$83,$fa,$4e);


  ct_cfb : array[0..63] of byte = ($1d,$9c,$d3,$8f,$2a,$12,$e1,$16,
                                   $28,$30,$e0,$71,$9d,$7a,$2e,$f3,
                                   $0b,$de,$7a,$07,$27,$7a,$c4,$49,
                                   $4d,$85,$4e,$06,$be,$a5,$4b,$aa,
                                   $a3,$84,$d5,$07,$1f,$23,$9c,$55,
                                   $a3,$e4,$d5,$87,$87,$b5,$d2,$fd,
                                   $57,$d8,$4d,$d9,$ad,$2c,$c5,$d1,
                                   $f1,$7e,$37,$b1,$3e,$c4,$26,$84);

  ct_ctr : array[0..63] of byte = ($81,$07,$98,$2d,$92,$73,$12,$40,
                                   $ba,$58,$c1,$c9,$32,$f7,$ea,$67,
                                   $f3,$a9,$8f,$eb,$25,$51,$fa,$c2,
                                   $5c,$17,$80,$be,$6b,$a0,$39,$e5,
                                   $dc,$1f,$eb,$c3,$81,$53,$af,$20,
                                   $bd,$15,$6d,$4b,$89,$65,$8a,$d5,
                                   $6c,$a1,$dc,$0e,$a0,$07,$5b,$c3,
                                   $8e,$3c,$b4,$6d,$9e,$af,$a1,$64);

  ct_ofb : array[0..63] of byte = ($1d,$9c,$d3,$8f,$2a,$12,$e1,$16,
                                   $07,$7c,$db,$a3,$73,$5a,$b2,$a4,
                                   $f9,$de,$06,$8b,$03,$e0,$a7,$ed,
                                   $33,$f1,$6f,$79,$ec,$76,$55,$75,
                                   $07,$6d,$24,$ae,$aa,$2d,$60,$ab,
                                   $2d,$ce,$34,$9f,$b2,$d6,$eb,$b5,
                                   $40,$83,$56,$a4,$fd,$38,$8c,$e6,
                                   $2c,$11,$16,$88,$4c,$67,$07,$76);

  ct_ecb : array[0..63] of byte = ($14,$e7,$78,$36,$6e,$88,$69,$95,
                                   $65,$5a,$28,$bd,$a8,$84,$98,$3e,
                                   $54,$48,$78,$c4,$d8,$61,$ae,$2b,
                                   $98,$ad,$ec,$ec,$b4,$5f,$1c,$b5,
                                   $6d,$be,$e7,$f1,$5f,$26,$50,$2f,
                                   $96,$19,$f6,$c3,$a6,$59,$d7,$f9,
                                   $74,$5c,$07,$81,$2a,$0d,$21,$7f,
                                   $9e,$98,$cb,$ec,$ce,$3e,$8a,$71);

var
  ct: array[0..63] of byte;

var
  {$ifdef BASM16}
    {$ifdef dumword}
      dummy: word;
    {$endif}
  {$endif}
  Context: TBFContext;

const
  Loops : longint = 8*1000000;  {512MB}


{---------------------------------------------------------------------------}
function test(px,py: pointer): string;
begin
  if compmem(px,py,64) then test := 'OK' else test := 'Error';
end;


{---------------------------------------------------------------------------}
procedure TestCFB;
var
  i: longint;
begin
  if BF_CFB_Init(key128, sizeof(key128), TBFBlock(IV), context)<>0 then begin
    writeln('*** Error CFB');
    exit;
  end;
  for i:=1 to Loops do begin
    if BF_CFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if BF_CBC_Init(key128, sizeof(key128), TBFBlock(IV), context)<>0 then begin
    writeln('*** Error CBC');
    exit;
  end;
  for i:=1 to Loops do begin
    if BF_CBC_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if BF_ECB_Init(key128, sizeof(key128), context)<>0 then begin
    writeln('*** Error ECB');
    exit;
  end;
  for i:=1 to Loops do begin
    if BF_ECB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if BF_CTR_Init(key128, sizeof(key128), TBFBlock(CTR), context)<>0 then begin
    writeln('*** Error CTR');
    exit;
  end;
  for i:=1 to Loops do begin
    if BF_CTR_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  if BF_OFB_Init(key128, sizeof(key128), TBFBlock(IV), context)<>0 then begin
    writeln('*** Error OFB');
    exit;
  end;
  for i:=1 to Loops do begin
    if BF_OFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
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
  tag: TBFBlock;
const
  tsdtag: TBFBlock = ($14,$AD,$28,$19,$8C,$22,$05,$9C);
begin
  if BF_OMAC_Init(key128, sizeof(key128), context)<>0 then begin
    writeln('*** Error OMAC Init');
    exit;
  end;
  for i:=1 to Loops do begin
    if BF_OMAC_Update(@plain, 64, context)<>0 then begin
      writeln('*** Error OMAC update');
      exit;
    end;
  end;
  BF_OMAC_Final(tag, context);
  if Loops=1 then begin
    write('OMAC test: ');
    if compmem(@tsdtag, @tag, sizeof(tag)) then writeln('OK') else writeln('Error');
 end;
end;



{---------------------------------------------------------------------------}
procedure TestEAX;
  {-Blowfish part of Tom St Denis' EAX_TV.TXT}
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
  {Initial key from hex32}
  move(hex32, key, sizeof(key));
  for n:=0 to 16 do begin
    err := BF_EAX_Init(key, 8, hex32, n, ctx);
    if err=0 then err := BF_EAX_Provide_Header(@hex32,n,ctx);
    if err=0 then err := BF_EAX_Encrypt(@hex32, @buf, n, ctx);
    if err=0 then begin
      BF_EAX_Final(tag, ctx);
      if n<16 then key := tag;
    end
    else begin
      writeln('*** Enc EAX error');
      exit;
    end;
  end;
  if not compmem(@buf16, @buf, sizeof(buf16)) then begin
    writeln('*** Enc EAX diff buf');
    exit;
  end;
  if not compmem(@tag16, @tag, sizeof(tag16)) then begin
    writeln('*** Enc EAX diff tag');
    exit;
  end;
  n := 16;
  err := BF_EAX_Init(key, 8, hex32, n, ctx);
  if err=0 then err := BF_EAX_Provide_Header(@hex32,n,ctx);
  if err=0 then err := BF_EAX_Decrypt(@buf16, @buf, n, ctx);
  if err=0 then BF_EAX_Final(tag, ctx)
  else begin
    writeln('*** Dec EAX error');
    exit;
  end;
  if not compmem(@hex32, @buf, sizeof(buf16)) then begin
    writeln('*** Dec EAX diff buf');
    exit;
  end;
  if not compmem(@tag16, @tag, sizeof(tag16)) then begin
    writeln('*** Dec EAX diff tag');
    exit;
  end;
  write('EAX  test: OK');
end;


var
  s: string[20];
  i: integer;
begin
  {$ifdef USEDLL}
    writeln('Test program for BF_DLL V',BF_DLL_Version,'   (C) 2004-2009  W.Ehrhardt');
  {$else}
    writeln('Test program for Blowfish modes    (C) 2004-2009  W.Ehrhardt');
  {$endif}
  {$ifdef D12Plus}
    s := shortstring(paramstr(1));
  {$else}
    s := paramstr(1);
  {$endif}
  BF_SetFastInit(true);
  for i:=1 to length(s) do s[i] := upcase(s[i]);
  if s='TEST' then begin
    {$ifdef BASM16}
      writeln('Context offset: ',ofs(context) and 7);
    {$endif}
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
    writeln('Usage: T_BF_WS  [ TEST | CBC | CFB | CTR | ECB | OFB | OMAC]');
    halt;
  end;
end.
