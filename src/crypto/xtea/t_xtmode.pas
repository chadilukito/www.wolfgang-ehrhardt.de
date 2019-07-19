{-Test prog for XTEA chaining modes, we Jan.2005}

program t_xtmode;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
    wincrt,
  {$endif}
  mem_util, xt_base, xt_cbc, xt_cfb, xt_ofb, xt_ecb, xt_ctr;

var
  ctx: TXTContext;

const
  key    : array[0..15] of byte = ($78,$56,$34,$12,$f0,$cd,$cb,$9a,
                                   $48,$37,$26,$15,$c0,$bf,$ae,$9d);

  IV     : array[0..07] of byte = ($00,$01,$02,$03,$04,$05,$06,$07);

  CTR    : array[0..07] of byte = ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7);

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
  ct: array[1..64] of byte;


{---------------------------------------------------------------------------}
procedure CBC_test;
  {-Test CBC routines}
begin
  {CBC Encrypt}
  if XT_CBC_Init(key, sizeof(key), TXTBlock(IV), ctx)<>0 then begin
    writeln('XT_Init error');
    halt;
  end;
  if XT_CBC_Encrypt(@plain, @ct, sizeof(ct_cbc), ctx)<>0 then begin
    writeln('XT_CBC_Encrypt');
    halt;
  end;
  writeln('CBC Enc: ', CompMem(@ct, @ct_cbc, sizeof(ct_cbc)));
  {CBC Decrypt}
  XT_CBC_Reset(TXTBlock(IV), ctx);
  if XT_CBC_Decrypt(@ct_cbc, @ct, sizeof(ct_cbc), ctx)<>0 then begin
    writeln('XT_CBC_Decrypt');
    halt;
  end;
  writeln('CBC Dec: ', CompMem(@ct, @plain, sizeof(plain)));
end;


{---------------------------------------------------------------------------}
procedure CFB_test;
  {-Test CFB routines}
begin
  {CFB Encrypt}
  if XT_CFB_Init(key, sizeof(key), TXTBlock(IV), ctx)<>0 then begin
    writeln('XT_Init error');
    halt;
  end;
  if XT_CFB_Encrypt(@plain, @ct, sizeof(ct_cfb), ctx)<>0 then begin
    writeln('XT_CFB_Encrypt');
    halt;
  end;
  writeln('CFB Enc: ', CompMem(@ct, @ct_cfb, sizeof(ct_cfb)));
  {CFB Decrypt}
  XT_CFB_Reset(TXTBlock(IV), ctx);
  if XT_CFB_Decrypt(@ct_cfb, @ct, sizeof(ct_cfb), ctx)<>0 then begin
    writeln('XT_CFB_Decrypt');
    halt;
  end;
  writeln('CFB Dec: ', CompMem(@ct, @plain, sizeof(plain)));
end;


{---------------------------------------------------------------------------}
procedure OFB_test;
  {-Test OFB routines}
begin
  {OFB Encrypt}
  if XT_OFB_Init(key, sizeof(key), TXTBlock(IV), ctx)<>0 then begin
    writeln('XT_Init error');
    halt;
  end;
  if XT_OFB_Encrypt(@plain, @ct, sizeof(ct_ofb), ctx)<>0 then begin
    writeln('XT_OFB_Encrypt');
    halt;
  end;
  writeln('OFB Enc: ', CompMem(@ct, @ct_ofb, sizeof(ct_ofb)));
  {OFB Dncrypt}
  XT_OFB_Reset(TXTBlock(IV), ctx);
  if XT_OFB_Decrypt(@ct_ofb, @ct, sizeof(ct_ofb), ctx)<>0 then begin
    writeln('XT_OFB_Decrypt');
    halt;
  end;
  writeln('OFB Dec: ', CompMem(@ct, @plain, sizeof(plain)));
end;


{---------------------------------------------------------------------------}
procedure ECB_Test;
  {-Test OFB routines, enc/dec two blocks from vectors.tst}
begin
  {ECB Encrypt}
  if XT_ECB_Init(key, sizeof(key), ctx)<>0 then begin
    writeln('XT_Init error');
    halt;
  end;
  if XT_ECB_Encrypt(@plain, @ct, sizeof(plain), ctx)<>0 then begin
    writeln('XT_ECB_Encrypt');
    halt;
  end;
  writeln('ECB Enc: ', CompMem(@ct, @ct_ecb, sizeof(ct_ecb)));
  {ECB Decrypt}
  XT_ECB_Reset(ctx);
  if XT_ECB_Decrypt(@ct_ecb, @ct, sizeof(ct_ecb), ctx)<>0 then begin
    writeln('XT_ECB_Decrypt');
    halt;
  end;
  writeln('ECB Dec: ', CompMem(@ct, @plain, sizeof(plain)));
end;


{---------------------------------------------------------------------------}
procedure CTR_test;
  {-Test CTR routines}
begin

  {CTR Encrypt}
  if XT_CTR_Init(key, sizeof(key), TXTBlock(CTR), ctx)<>0 then begin
    writeln('XT_Init error');
    halt;
  end;
  if XT_CTR_Encrypt(@plain, @ct, sizeof(ct_ctr), ctx)<>0 then begin
    writeln('XT_CTR_Encrypt');
    halt;
  end;
  writeln('CTR Enc: ', CompMem(@ct, @ct_ctr, sizeof(ct_ctr)));

  {CTR Decrypt}
  XT_CTR_Reset(TXTBlock(CTR), ctx);
  if XT_CTR_Decrypt(@ct_ctr, @ct, sizeof(ct_ctr), ctx)<>0 then begin
    writeln('XT_CTR_Decrypt');
    halt;
  end;
  writeln('CTR Dec: ', CompMem(@ct, @plain, sizeof(ct_ctr)));
end;



begin
  writeln('Test program for XTEA chaining modes    (C) 2005  W.Ehrhardt');
  CBC_test;
  CFB_test;
  OFB_test;
  ECB_test;
  CTR_test;
end.
