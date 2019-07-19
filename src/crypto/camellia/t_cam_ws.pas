{-Speed/Test prog for Camellia modes, we Aug.2008}

program T_CAM_WS;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
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
      CAM_Intv,
    {$else}
      CAM_Intf,
    {$endif}
  {$else}
    CAM_Base, CAM_CTR, CAM_CFB, CAM_OFB, CAM_CBC, CAM_ECB, CAM_OMAC, CAM_EAX, CAM_CPRF,
  {$endif}
  mem_util;

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

  {Test vectors from CryptoBench using Wei Dai's Crypto++ Version 5+}
  {http://www.addario.org/files/CryptoBench%20v1.0.1.zip}
  {http://mywebpage.netscape.com/cryptobench/}

  ct_cbc : array[0..63] of byte = ($16,$07,$cf,$49,$4b,$36,$bb,$f0,
                                   $0d,$ae,$b0,$b5,$03,$c8,$31,$ab,
                                   $a2,$f2,$cf,$67,$16,$29,$ef,$78,
                                   $40,$c5,$a5,$df,$b5,$07,$48,$87,
                                   $0f,$06,$16,$50,$08,$cf,$8b,$8b,
                                   $5a,$63,$58,$63,$62,$54,$3e,$54,
                                   $e7,$20,$8a,$2c,$a8,$9c,$c2,$1a,
                                   $ac,$d5,$6a,$aa,$6f,$b9,$82,$59);

  ct_cfb : array[0..63] of byte = ($14,$f7,$64,$61,$87,$81,$7e,$b5,
                                   $86,$59,$91,$46,$b8,$2b,$d7,$19,
                                   $a5,$3d,$28,$bb,$82,$df,$74,$11,
                                   $03,$ea,$4f,$92,$1a,$44,$88,$0b,
                                   $9c,$21,$57,$a6,$64,$62,$6d,$1d,
                                   $ef,$9e,$a4,$20,$fd,$e6,$9b,$96,
                                   $74,$2a,$25,$f0,$54,$23,$40,$c7,
                                   $ba,$ef,$24,$ca,$84,$82,$bb,$09);

  ct_ctr : array[0..63] of byte = ($b8,$09,$14,$08,$77,$dd,$16,$c0,
                                   $76,$78,$09,$04,$f8,$3d,$ed,$11,
                                   $bb,$41,$e6,$4e,$9b,$f1,$76,$ce,
                                   $05,$d4,$18,$6b,$25,$86,$d4,$c9,
                                   $49,$e8,$2f,$dc,$5d,$6e,$78,$ab,
                                   $78,$13,$63,$e5,$17,$81,$fc,$9b,
                                   $73,$1a,$3c,$05,$83,$97,$9a,$92,
                                   $6e,$7f,$e0,$b8,$a2,$05,$ac,$29);

  ct_ofb : array[0..63] of byte = ($14,$f7,$64,$61,$87,$81,$7e,$b5,
                                   $86,$59,$91,$46,$b8,$2b,$d7,$19,
                                   $97,$32,$91,$71,$6c,$4d,$82,$d0,
                                   $1a,$07,$9e,$6d,$f7,$00,$e6,$eb,
                                   $0e,$f0,$60,$3e,$2e,$e5,$34,$c1,
                                   $74,$f4,$4a,$86,$78,$a0,$1f,$5b,
                                   $a9,$97,$8a,$35,$4c,$35,$c7,$a0,
                                   $52,$c3,$82,$18,$18,$3c,$be,$71);

  ct_ecb : array[0..63] of byte = ($43,$2f,$c5,$dc,$d6,$28,$11,$5b,
                                   $7c,$38,$8d,$77,$0b,$27,$0c,$96,
                                   $0b,$e1,$f1,$40,$23,$78,$2a,$22,
                                   $e8,$38,$4c,$5a,$bb,$7f,$ab,$2b,
                                   $a0,$a1,$ab,$cd,$18,$93,$ab,$6f,
                                   $e0,$fe,$5b,$65,$df,$5f,$86,$36,
                                   $e6,$19,$25,$e0,$d5,$df,$aa,$9b,
                                   $b2,$9f,$81,$5b,$30,$76,$e5,$1a);

var
  ct,pt: array[0..63] of byte;

var
  Context: TCAMContext;

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
  fillchar(pt, sizeof(pt),0);
  fillchar(ct, sizeof(ct),0);
  if CAM_CFB_Init(key128, 8*sizeof(key128), TCAMBlock(IV), context)<>0 then begin
    writeln('*** Error CFB');
    exit;
  end;
  for i:=1 to Loops do begin
    if CAM_CFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CFB');
      exit;
    end;
  end;
  if Loops=1 then begin
    CAM_CFB_Reset(TCAMBlock(IV), context);
    if CAM_CFB_Decrypt(@ct, @pt, sizeof(plain), context)<>0 then begin
      writeln('*** Error CFB');
      exit;
    end;
    write('CFB  test - Enc: ', test(@ct,@ct_cfb));
    writeln(', Dec: ', test(@pt,@plain));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestCBC;
var
  i: longint;
begin
  fillchar(pt, sizeof(pt),0);
  fillchar(ct, sizeof(ct),0);
  if CAM_CBC_Init(key128, 8*sizeof(key128), TCAMBlock(IV), context)<>0 then begin
    writeln('*** Error CBC');
    exit;
  end;
  for i:=1 to Loops do begin
    if CAM_CBC_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CBC');
      exit;
    end;
  end;
  if Loops=1 then begin
    CAM_CBC_Reset(TCAMBlock(IV), context);
    if CAM_CBC_Decrypt(@ct, @pt, sizeof(plain), context)<>0 then begin
      writeln('*** Error CBC');
      exit;
    end;
    write('CBC  test - Enc: ', test(@ct,@ct_cbc));
    writeln(', Dec: ', test(@pt,@plain));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestECB;
var
  i: longint;
begin
  fillchar(pt, sizeof(pt),0);
  fillchar(ct, sizeof(ct),0);
  if CAM_ECB_Init(key128, 8*sizeof(key128), context)<>0 then begin
    writeln('*** Error ECB');
    exit;
  end;
  for i:=1 to Loops do begin
    if CAM_ECB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error ECB');
      exit;
    end;
  end;
  if Loops=1 then begin
    CAM_ECB_Reset(context);
    if CAM_ECB_Decrypt(@ct, @pt, sizeof(plain), context)<>0 then begin
      writeln('*** Error ECB');
      exit;
    end;
    write('ECB  test - Enc: ', test(@ct,@ct_ECB));
    writeln(', Dec: ', test(@pt,@plain));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestCTR;
var
  i: longint;
begin
  fillchar(pt, sizeof(pt),0);
  fillchar(ct, sizeof(ct),0);
  if CAM_CTR_Init(key128, 8*sizeof(key128), TCAMBlock(CTR), context)<>0 then begin
    writeln('*** Error CTR');
    exit;
  end;
  {$ifdef FPC_ProcVar}
    if CAM_SetIncProc(@CAM_IncMSBFull, context)<>0 then begin
      writeln('*** Error SetIncProc');
      exit;
    end;
    if (context.IncProc=@CAM_IncMSBFull) then writeln('OK (IncProc)')
    else writeln('IncProc not recognized');
  {$else}
    if CAM_SetIncProc(CAM_IncMSBFull, context)<>0 then begin
      writeln('*** Error SetIncProc');
      exit;
    end;
    if (@context.IncProc=@CAM_IncMSBFull) then writeln('OK (IncProc)')
    else writeln('IncProc not recognized');
  {$endif}
  for i:=1 to Loops do begin
    if CAM_CTR_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error CTR');
      exit;
    end;
  end;
  if Loops=1 then begin
    CAM_CTR_Reset(TCAMBlock(CTR), context);
    if CAM_CTR_Decrypt(@ct, @pt, sizeof(plain), context)<>0 then begin
      writeln('*** Error CTR');
      exit;
    end;
    write('CTR  test - Enc: ', test(@ct,@ct_ctr));
    writeln(', Dec: ', test(@pt,@plain));
  end;
end;


{---------------------------------------------------------------------------}
procedure TestOFB;
var
  i: longint;
begin
  fillchar(pt, sizeof(pt),0);
  fillchar(ct, sizeof(ct),0);
  if CAM_OFB_Init(key128, 8*sizeof(key128), TCAMBlock(IV), context)<>0 then begin
    writeln('*** Error OFB');
    exit;
  end;
  for i:=1 to Loops do begin
    if CAM_OFB_Encrypt(@plain, @ct, sizeof(plain), context)<>0 then begin
      writeln('*** Error OFB');
      exit;
    end;
  end;
  if Loops=1 then begin
    CAM_OFB_Reset(TCAMBlock(IV), context);
    if CAM_OFB_Decrypt(@ct, @pt, sizeof(plain), context)<>0 then begin
      writeln('*** Error OFB');
      exit;
    end;
    write('OFB  test - Enc: ', test(@ct,@ct_ofb));
    writeln(', Dec: ', test(@pt,@plain));
  end;
end;



{---------------------------------------------------------------------------}
procedure TestOMAC;
var
  i: longint;
  tag: TCAMBlock;
  {from draft-kato-ipsec-camellia-cmac96and128-02.txt}
const
  drafttag: TCAMBlock = ($c2,$69,$9a,$6e,$ba,$55,$ce,$9d,
                         $93,$9a,$8a,$4e,$19,$46,$6e,$e9);
begin
  if CAM_OMAC_Init(key128, 128, context)<>0 then begin
    writeln('*** Error OMAC Init');
    exit;
  end;
  for i:=1 to Loops do begin
    if CAM_OMAC_Update(@plain, 64, context)<>0 then begin
      writeln('*** Error OMAC update');
      exit;
    end;
  end;
  CAM_OMAC_Final(tag, context);
  if Loops=1 then begin
    write('OMAC test: ');
    if compmem(@drafttag, @tag, sizeof(tag)) then writeln('OK') else writeln('Error');
 end;
end;



{---------------------------------------------------------------------------}
procedure TestEAX;
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
  err: integer;
  n: word;
  ctx: TCAM_EAXContext;
  key, tag: TCAMBlock;
  buf: array[0..63] of byte;
begin
  {Initial key from hex32}
  move(hex32, key, sizeof(key));
  for n:=0 to 32 do begin
    err := CAM_EAX_Init(key, 128, hex32, n, ctx);
    if err=0 then err := CAM_EAX_Provide_Header(@hex32,n,ctx);
    if err=0 then err := CAM_EAX_Encrypt(@hex32, @buf, n, ctx);
    if err=0 then begin
      CAM_EAX_Final(tag, ctx);
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
  err := CAM_EAX_Init(key, 128, hex32, n, ctx);
  if err=0 then err := CAM_EAX_Provide_Header(@hex32,n,ctx);
  if err=0 then err := CAM_EAX_Decrypt(@buf32, @buf, n, ctx);
  if err=0 then CAM_EAX_Final(tag, ctx)
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
  writeln('EAX  test: OK  (incremental API)');
  {All-in-One functions}
  move(hex32, key, sizeof(key));
  for n:=0 to 32 do begin
    err := CAM_EAX_Enc_Auth(tag,key,128,hex32,n,@hex32,n,@hex32,n,@buf);
    if err<>0 then begin
      writeln('*** CAM_EAX_Enc_Auth error');
      exit;
    end
    else if n<32 then key := tag;
  end;
  if not compmem(@buf32, @buf, sizeof(buf32)) then begin
    writeln('*** CAM_EAX_Enc_Auth diff buf');
    exit;
  end;
  if not compmem(@tag32, @tag, sizeof(tag32)) then begin
    writeln('*** CAM_EAX_Enc_Auth diff tag');
    exit;
  end;
  n := 32;
  err := CAM_EAX_Dec_Veri(@tag32,sizeof(tag32),key,128,hex32,n,@hex32,n,@buf32,n,@buf);
  if err<>0 then begin
    writeln('*** CAM_EAX_Dec_Veri error');
    exit;
  end;
  if not compmem(@hex32, @buf, sizeof(buf32)) then begin
    writeln('*** CAM_EAX_Dec_Veri diff buf');
    exit;
  end;
  writeln('EAX  test: OK  (all-in-one functions)');
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
    writeln('Test program for CAM_DLL V',CAM_DLL_Version,'   (C) 2009  W.Ehrhardt');
  {$else}
    writeln('Test program for Camellia modes    (C) 2009  W.Ehrhardt');
  {$endif}
  s := paramstr(1);
  CAM_SetFastInit(true);
  for i:=1 to length(s) do s[i] := upcase(s[i]);
  if s='TEST' then begin
    Loops := 1;
    writeln('Selftest CPRF-128: ', CAM_CPRF128_selftest);
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
    writeln('Usage: T_CAM_WS  [ TEST | CBC | CFB | CTR | ECB | OFB | OMAC]');
    halt;
  end;
end.
