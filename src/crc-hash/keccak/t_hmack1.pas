program t_hmack1;

{-HMAC-Keccak known answer tests, WE Nov.2012}

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}


uses
  {$ifdef WINCRT} WinCRT, {$endif}
  BTypes, mem_util, keccak_n, hmackecc;


var
  ctx: THMACKec_Context;
  mac: TKeccakMaxDigest;


{Vectors from http://www.di-mgt.com.au/hmac_sha3_testvectors.html}

{---------------------------------------------------------------------------}
procedure test_case_1;
const
  key : array[0.. 19] of byte = ($0b,$0b,$0b,$0b,$0b,$0b,$0b,$0b,
                                 $0b,$0b,$0b,$0b,$0b,$0b,$0b,$0b,
                                 $0b,$0b,$0b,$0b);
  data: array[0..  7] of byte = ($48,$69,$20,$54,$68,$65,$72,$65);
  d224: array[0.. 27] of byte = ($b7,$3d,$59,$5a,$2b,$a9,$af,$81,
                                 $5e,$9f,$2b,$4e,$53,$e7,$85,$81,
                                 $eb,$d3,$4a,$80,$b3,$bb,$aa,$c4,
                                 $e7,$02,$c4,$cc);
  d256: array[0.. 31] of byte = ($96,$63,$d1,$0c,$73,$ee,$29,$40,
                                 $54,$dc,$9f,$af,$95,$64,$7c,$b9,
                                 $97,$31,$d1,$22,$10,$ff,$70,$75,
                                 $fb,$3d,$33,$95,$ab,$fb,$98,$21);
  d384: array[0.. 31] of byte = ($89,$2d,$fd,$f5,$d5,$1e,$46,$79,
                                 $bf,$32,$0c,$d1,$6d,$4c,$9d,$c6,
                                 $f7,$49,$74,$46,$08,$e0,$03,$ad,
                                 $d7,$fb,$a8,$94,$ac,$ff,$87,$36);
  d512: array[0.. 63] of byte = ($88,$52,$c6,$3b,$e8,$cf,$c2,$15,
                                 $41,$a4,$ee,$5e,$5a,$9a,$85,$2f,
                                 $c2,$f7,$a9,$ad,$ec,$2f,$f3,$a1,
                                 $37,$18,$ab,$4e,$d8,$1a,$ae,$a0,
                                 $b8,$7b,$7e,$b3,$97,$32,$35,$48,
                                 $e2,$61,$a6,$4e,$7f,$c7,$51,$98,
                                 $f6,$66,$3a,$11,$b2,$2c,$d9,$57,
                                 $f7,$c8,$ec,$85,$8a,$1c,$77,$55);
begin
  writeln('Test case 1:');

  hmac_keccak_init(ctx, 224, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-224: ', compmem(@mac, @d224, sizeof(d224)));

  hmac_keccak_init(ctx, 256, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-256: ', compmem(@mac, @d256, sizeof(d256)));

  hmac_keccak_init(ctx, 384, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-384: ', compmem(@mac, @d384, sizeof(d384)));

  hmac_keccak_init(ctx, 512, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-512: ', compmem(@mac, @d512, sizeof(d512)));

end;



{---------------------------------------------------------------------------}
procedure test_case_2;
const
  key : array[0..  3] of byte = ($4a,$65,$66,$65);
  data: array[0.. 27] of byte = ($77,$68,$61,$74,$20,$64,$6f,$20,
                                 $79,$61,$20,$77,$61,$6e,$74,$20,
                                 $66,$6f,$72,$20,$6e,$6f,$74,$68,
                                 $69,$6e,$67,$3f);
  d224: array[0.. 27] of byte = ($e8,$24,$fe,$c9,$6c,$07,$4f,$22,
                                 $f9,$92,$35,$bb,$94,$2d,$a1,$98,
                                 $26,$64,$ab,$69,$2c,$a8,$50,$10,
                                 $53,$cb,$d4,$14);
  d256: array[0.. 31] of byte = ($aa,$9a,$ed,$44,$8c,$7a,$bc,$8b,
                                 $5e,$32,$6f,$fa,$6a,$01,$cd,$ed,
                                 $f7,$b4,$b8,$31,$88,$14,$68,$c0,
                                 $44,$ba,$8d,$d4,$56,$63,$69,$a1);
  d384: array[0.. 47] of byte = ($5a,$f5,$c9,$a7,$7a,$23,$a6,$a9,
                                 $3d,$80,$64,$9e,$56,$2a,$b7,$7f,
                                 $4f,$35,$52,$e3,$c5,$ca,$ff,$d9,
                                 $3b,$df,$8b,$3c,$fc,$69,$20,$e3,
                                 $02,$3f,$c2,$67,$75,$d9,$df,$1f,
                                 $3c,$94,$61,$31,$46,$ad,$2c,$9d);
  d512: array[0.. 63] of byte = ($c2,$96,$2e,$5b,$be,$12,$38,$00,
                                 $78,$52,$f7,$9d,$81,$4d,$bb,$ec,
                                 $d4,$68,$2e,$6f,$09,$7d,$37,$a3,
                                 $63,$58,$7c,$03,$bf,$a2,$eb,$08,
                                 $59,$d8,$d9,$c7,$01,$e0,$4c,$ec,
                                 $ec,$fd,$3d,$d7,$bf,$d4,$38,$f2,
                                 $0b,$8b,$64,$8e,$01,$bf,$8c,$11,
                                 $d2,$68,$24,$b9,$6c,$eb,$bd,$cb);
begin
  writeln('Test case 2:');

  hmac_keccak_init(ctx, 224, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-224: ', compmem(@mac, @d224, sizeof(d224)));

  hmac_keccak_init(ctx, 256, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-256: ', compmem(@mac, @d256, sizeof(d256)));

  hmac_keccak_init(ctx, 384, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-384: ', compmem(@mac, @d384, sizeof(d384)));

  hmac_keccak_init(ctx, 512, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-512: ', compmem(@mac, @d512, sizeof(d512)));

end;

{---------------------------------------------------------------------------}
procedure test_case_3;
const
  key : array[0.. 19] of byte = ($aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa);
  data: array[0.. 49] of byte = ($dd,$dd,$dd,$dd,$dd,$dd,$dd,$dd,
                                 $dd,$dd,$dd,$dd,$dd,$dd,$dd,$dd,
                                 $dd,$dd,$dd,$dd,$dd,$dd,$dd,$dd,
                                 $dd,$dd,$dd,$dd,$dd,$dd,$dd,$dd,
                                 $dd,$dd,$dd,$dd,$dd,$dd,$dd,$dd,
                                 $dd,$dd,$dd,$dd,$dd,$dd,$dd,$dd,
                                 $dd,$dd);
  d224: array[0.. 27] of byte = ($77,$0d,$f3,$8c,$99,$d6,$e2,$ba,
                                 $cd,$68,$05,$6d,$cf,$e0,$7d,$4c,
                                 $89,$ae,$20,$b2,$68,$6a,$61,$85,
                                 $e1,$fa,$a4,$49);
  d256: array[0.. 31] of byte = ($95,$f4,$3e,$50,$f8,$df,$80,$a2,
                                 $19,$77,$d5,$1a,$8d,$b3,$ba,$57,
                                 $2d,$cd,$71,$db,$24,$68,$7e,$6f,
                                 $86,$f4,$7c,$11,$39,$b2,$62,$60);
  d384: array[0.. 47] of byte = ($42,$43,$c2,$9f,$22,$01,$99,$2f,
                                 $f9,$64,$41,$e3,$b9,$1f,$f8,$1d,
                                 $8c,$60,$1d,$70,$6f,$bc,$83,$25,
                                 $26,$84,$a4,$bc,$51,$10,$1c,$a9,
                                 $b2,$c0,$6d,$dd,$03,$67,$73,$03,
                                 $c5,$02,$ac,$53,$31,$75,$2a,$3c);
  d512: array[0.. 63] of byte = ($eb,$0e,$d9,$58,$0e,$0e,$c1,$1f,
                                 $c6,$6c,$bb,$64,$6b,$1b,$e9,$04,
                                 $ea,$ff,$6d,$a4,$55,$6d,$93,$34,
                                 $f6,$5e,$e4,$b2,$c8,$57,$39,$15,
                                 $7b,$ae,$90,$27,$c5,$15,$05,$e4,
                                 $9d,$1b,$b8,$1c,$fa,$55,$e6,$82,
                                 $2d,$b5,$52,$62,$d5,$a2,$52,$c0,
                                 $88,$a2,$9a,$5e,$95,$b8,$4a,$66);
begin
  writeln('Test case 3:');

  hmac_keccak_init(ctx, 224, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-224: ', compmem(@mac, @d224, sizeof(d224)));

  hmac_keccak_init(ctx, 256, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-256: ', compmem(@mac, @d256, sizeof(d256)));

  hmac_keccak_init(ctx, 384, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-384: ', compmem(@mac, @d384, sizeof(d384)));

  hmac_keccak_init(ctx, 512, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-512: ', compmem(@mac, @d512, sizeof(d512)));

end;


{---------------------------------------------------------------------------}
procedure test_case_4;
const
  key : array[0.. 24] of byte = ($01,$02,$03,$04,$05,$06,$07,$08,
                                 $09,$0a,$0b,$0c,$0d,$0e,$0f,$10,
                                 $11,$12,$13,$14,$15,$16,$17,$18,
                                 $19);
  data: array[0.. 49] of byte = ($cd,$cd,$cd,$cd,$cd,$cd,$cd,$cd,
                                 $cd,$cd,$cd,$cd,$cd,$cd,$cd,$cd,
                                 $cd,$cd,$cd,$cd,$cd,$cd,$cd,$cd,
                                 $cd,$cd,$cd,$cd,$cd,$cd,$cd,$cd,
                                 $cd,$cd,$cd,$cd,$cd,$cd,$cd,$cd,
                                 $cd,$cd,$cd,$cd,$cd,$cd,$cd,$cd,
                                 $cd,$cd);
  d224: array[0.. 27] of byte = ($30,$5a,$8f,$2d,$fb,$94,$ba,$d2,
                                 $88,$61,$a0,$3c,$bc,$4d,$59,$0f,
                                 $eb,$e7,$75,$c5,$8c,$b4,$96,$1c,
                                 $28,$42,$8a,$0b);
  d256: array[0.. 31] of byte = ($63,$31,$ba,$9b,$4a,$f5,$80,$4a,
                                 $68,$72,$5b,$36,$63,$eb,$74,$81,
                                 $44,$94,$b6,$3c,$60,$93,$e3,$5f,
                                 $b3,$20,$a8,$5d,$50,$79,$36,$fd);
  d384: array[0.. 47] of byte = ($b7,$30,$72,$4d,$3d,$40,$90,$cd,
                                 $a1,$be,$79,$9f,$63,$ac,$bb,$e3,
                                 $89,$fe,$f7,$79,$2f,$c1,$86,$76,
                                 $fa,$54,$53,$aa,$b3,$98,$66,$46,
                                 $50,$ed,$02,$9c,$34,$98,$bb,$e8,
                                 $05,$6f,$06,$c6,$58,$e1,$e6,$93);
  d512: array[0.. 63] of byte = ($b4,$61,$93,$bb,$59,$f4,$f6,$96,
                                 $bf,$70,$25,$97,$61,$6d,$a9,$1e,
                                 $2a,$45,$58,$a5,$93,$f4,$b0,$15,
                                 $e6,$91,$41,$ba,$81,$e1,$e5,$0e,
                                 $a5,$80,$83,$4c,$2b,$87,$f8,$7b,
                                 $aa,$25,$a3,$a0,$3b,$fc,$9b,$b3,
                                 $89,$84,$7f,$2d,$c8,$20,$be,$ae,
                                 $69,$d3,$0c,$4b,$b7,$53,$69,$cb);
begin
  writeln('Test case 4:');

  hmac_keccak_init(ctx, 224, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-224: ', compmem(@mac, @d224, sizeof(d224)));

  hmac_keccak_init(ctx, 256, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-256: ', compmem(@mac, @d256, sizeof(d256)));

  hmac_keccak_init(ctx, 384, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-384: ', compmem(@mac, @d384, sizeof(d384)));

  hmac_keccak_init(ctx, 512, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-512: ', compmem(@mac, @d512, sizeof(d512)));

end;



{---------------------------------------------------------------------------}
procedure test_case_5;
const
  key : array[0.. 19] of byte = ($0c,$0c,$0c,$0c,$0c,$0c,$0c,$0c,
                                 $0c,$0c,$0c,$0c,$0c,$0c,$0c,$0c,
                                 $0c,$0c,$0c,$0c);
  data: array[0.. 19] of byte = ($54,$65,$73,$74,$20,$57,$69,$74,
                                 $68,$20,$54,$72,$75,$6e,$63,$61,
                                 $74,$69,$6f,$6e);
  d224: array[0.. 15] of byte = ($f5,$2b,$bc,$fd,$65,$42,$64,$e7,
                                 $13,$30,$85,$c5,$e6,$9b,$72,$c3);
  d256: array[0.. 15] of byte = ($74,$5e,$7e,$68,$7f,$83,$35,$28,
                                 $0d,$54,$20,$2e,$f1,$3c,$ec,$c6);
  d384: array[0.. 15] of byte = ($fa,$9a,$ea,$2b,$c1,$e1,$81,$e4,
                                 $7c,$bb,$8c,$3d,$f2,$43,$81,$4d);
  d512: array[0.. 15] of byte = ($04,$c9,$29,$fe,$ad,$43,$4b,$ba,
                                 $19,$0d,$ac,$fa,$55,$4c,$e3,$f5);
begin
  writeln('Test case 5:');

  hmac_keccak_init(ctx, 224, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-224: ', compmem(@mac, @d224, sizeof(d224)));

  hmac_keccak_init(ctx, 256, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-256: ', compmem(@mac, @d256, sizeof(d256)));

  hmac_keccak_init(ctx, 384, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-384: ', compmem(@mac, @d384, sizeof(d384)));

  hmac_keccak_init(ctx, 512, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-512: ', compmem(@mac, @d512, sizeof(d512)));

end;


{---------------------------------------------------------------------------}
procedure test_case_6;
const
  key : array[0..130] of byte = ($aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa);
  data: array[0.. 53] of byte = ($54,$65,$73,$74,$20,$55,$73,$69,
                                 $6e,$67,$20,$4c,$61,$72,$67,$65,
                                 $72,$20,$54,$68,$61,$6e,$20,$42,
                                 $6c,$6f,$63,$6b,$2d,$53,$69,$7a,
                                 $65,$20,$4b,$65,$79,$20,$2d,$20,
                                 $48,$61,$73,$68,$20,$4b,$65,$79,
                                 $20,$46,$69,$72,$73,$74);
  d224: array[0.. 27] of byte = ($e7,$a5,$2d,$fa,$45,$f9,$5a,$21,
                                 $7c,$10,$00,$66,$b2,$39,$aa,$8a,
                                 $d5,$19,$be,$9b,$35,$d6,$67,$26,
                                 $8b,$1b,$57,$ff);
  d256: array[0.. 31] of byte = ($b4,$d0,$cd,$ee,$7e,$c2,$ba,$81,
                                 $a8,$8b,$86,$91,$89,$58,$31,$23,
                                 $00,$a1,$56,$22,$37,$79,$29,$a0,
                                 $54,$a9,$ce,$3a,$e1,$fa,$c2,$b6);
  d384: array[0.. 47] of byte = ($d6,$24,$82,$ef,$60,$1d,$78,$47,
                                 $43,$9b,$55,$23,$6e,$96,$79,$38,
                                 $8f,$fc,$d5,$3c,$62,$cd,$12,$6f,
                                 $39,$be,$6e,$a6,$3d,$e7,$62,$e2,
                                 $6c,$d5,$97,$4c,$b9,$a8,$de,$40,
                                 $1b,$78,$6b,$55,$55,$04,$0f,$6f);
  d512: array[0.. 63] of byte = ($d0,$58,$88,$a6,$eb,$f8,$46,$04,
                                 $23,$ea,$7b,$c8,$5e,$a4,$ff,$da,
                                 $84,$7b,$32,$df,$32,$29,$1d,$2c,
                                 $e1,$15,$fd,$18,$77,$07,$32,$5c,
                                 $7c,$e4,$f7,$18,$80,$d9,$10,$08,
                                 $08,$4c,$e2,$4a,$38,$79,$5d,$20,
                                 $e6,$a2,$83,$28,$a0,$f0,$71,$2d,
                                 $c3,$82,$53,$37,$0d,$a3,$eb,$b5);
begin
  writeln('Test case 6:');

  hmac_keccak_init(ctx, 224, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-224: ', compmem(@mac, @d224, sizeof(d224)));

  hmac_keccak_init(ctx, 256, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-256: ', compmem(@mac, @d256, sizeof(d256)));

  hmac_keccak_init(ctx, 384, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-384: ', compmem(@mac, @d384, sizeof(d384)));

  hmac_keccak_init(ctx, 512, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-512: ', compmem(@mac, @d512, sizeof(d512)));

end;


{---------------------------------------------------------------------------}
procedure test_case_6a;
const
  key : array[0..146] of byte = ($aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa);
  data: array[0.. 53] of byte = ($54,$65,$73,$74,$20,$55,$73,$69,
                                 $6e,$67,$20,$4c,$61,$72,$67,$65,
                                 $72,$20,$54,$68,$61,$6e,$20,$42,
                                 $6c,$6f,$63,$6b,$2d,$53,$69,$7a,
                                 $65,$20,$4b,$65,$79,$20,$2d,$20,
                                 $48,$61,$73,$68,$20,$4b,$65,$79,
                                 $20,$46,$69,$72,$73,$74);
  d224: array[0.. 27] of byte = ($4d,$c9,$ce,$18,$32,$81,$ce,$75,
                                 $1b,$fc,$55,$66,$7c,$07,$4a,$07,
                                 $7e,$07,$51,$bf,$40,$c5,$3f,$9e,
                                 $6a,$83,$25,$0f);
  d256: array[0.. 31] of byte = ($ea,$68,$d6,$57,$1d,$cb,$46,$69,
                                 $fd,$97,$c5,$95,$32,$69,$c7,$41,
                                 $26,$a1,$02,$b1,$f9,$7a,$f6,$bd,
                                 $ba,$55,$33,$cd,$e5,$1e,$8a,$cc);
  d384: array[0.. 47] of byte = ($0c,$08,$17,$f7,$4b,$18,$2b,$ae,
                                 $b9,$33,$e4,$e7,$07,$4a,$0c,$b1,
                                 $c6,$19,$dc,$e7,$f1,$15,$49,$ec,
                                 $95,$05,$d2,$d6,$c8,$29,$59,$d4,
                                 $51,$bd,$31,$65,$4f,$58,$eb,$d5,
                                 $69,$ac,$63,$23,$dc,$62,$d4,$08);
  d512: array[0.. 63] of byte = ($0f,$01,$da,$58,$d5,$2a,$7e,$4e,
                                 $f3,$38,$6b,$f7,$ed,$b6,$66,$25,
                                 $ff,$5c,$25,$38,$5c,$38,$87,$d3,
                                 $ac,$99,$18,$c0,$82,$8b,$a8,$0c,
                                 $0d,$b2,$de,$5b,$ca,$33,$98,$f9,
                                 $69,$4f,$7f,$d5,$15,$35,$20,$3a,
                                 $9e,$1f,$73,$ac,$4d,$90,$19,$38,
                                 $3b,$55,$20,$bc,$26,$d2,$d6,$54);


begin
  writeln('Test case 6a:');

  hmac_keccak_init(ctx, 224, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-224: ', compmem(@mac, @d224, sizeof(d224)));

  hmac_keccak_init(ctx, 256, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-256: ', compmem(@mac, @d256, sizeof(d256)));

  hmac_keccak_init(ctx, 384, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-384: ', compmem(@mac, @d384, sizeof(d384)));

  hmac_keccak_init(ctx, 512, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-512: ', compmem(@mac, @d512, sizeof(d512)));

end;


{---------------------------------------------------------------------------}
procedure test_case_7;
const
  key : array[0..130] of byte = ($aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa);
  data: array[0..151] of byte = ($54,$68,$69,$73,$20,$69,$73,$20,
                                 $61,$20,$74,$65,$73,$74,$20,$75,
                                 $73,$69,$6e,$67,$20,$61,$20,$6c,
                                 $61,$72,$67,$65,$72,$20,$74,$68,
                                 $61,$6e,$20,$62,$6c,$6f,$63,$6b,
                                 $2d,$73,$69,$7a,$65,$20,$6b,$65,
                                 $79,$20,$61,$6e,$64,$20,$61,$20,
                                 $6c,$61,$72,$67,$65,$72,$20,$74,
                                 $68,$61,$6e,$20,$62,$6c,$6f,$63,
                                 $6b,$2d,$73,$69,$7a,$65,$20,$64,
                                 $61,$74,$61,$2e,$20,$54,$68,$65,
                                 $20,$6b,$65,$79,$20,$6e,$65,$65,
                                 $64,$73,$20,$74,$6f,$20,$62,$65,
                                 $20,$68,$61,$73,$68,$65,$64,$20,
                                 $62,$65,$66,$6f,$72,$65,$20,$62,
                                 $65,$69,$6e,$67,$20,$75,$73,$65,
                                 $64,$20,$62,$79,$20,$74,$68,$65,
                                 $20,$48,$4d,$41,$43,$20,$61,$6c,
                                 $67,$6f,$72,$69,$74,$68,$6d,$2e);
  d224: array[0.. 27] of byte = ($ba,$13,$00,$94,$05,$a9,$29,$f3,
                                 $98,$b3,$48,$88,$5c,$aa,$54,$19,
                                 $19,$1b,$b9,$48,$ad,$a3,$21,$94,
                                 $af,$c8,$41,$04);
  d256: array[0.. 31] of byte = ($1f,$dc,$8c,$b4,$e2,$7d,$07,$c1,
                                 $0d,$89,$7d,$ec,$39,$c2,$17,$79,
                                 $2a,$6e,$64,$fa,$9c,$63,$a7,$7c,
                                 $e4,$2a,$d1,$06,$ef,$28,$4e,$02);
  d384: array[0.. 47] of byte = ($48,$60,$ea,$19,$1a,$c3,$49,$94,
                                 $cf,$88,$95,$7a,$fe,$5a,$83,$6e,
                                 $f3,$6e,$4c,$c1,$a6,$6d,$75,$bf,
                                 $77,$de,$fb,$75,$76,$12,$2d,$75,
                                 $f6,$06,$60,$e4,$cf,$73,$1c,$6e,
                                 $ff,$ac,$06,$40,$27,$87,$e2,$b9);
  d512: array[0.. 63] of byte = ($2c,$6b,$97,$48,$d3,$5c,$4c,$8d,
                                 $b0,$b4,$40,$7d,$d2,$ed,$23,$81,
                                 $f1,$33,$bd,$bd,$1d,$fa,$a6,$9e,
                                 $30,$05,$1e,$b6,$ba,$df,$cc,$a6,
                                 $42,$99,$b8,$8a,$e0,$5f,$db,$d3,
                                 $dd,$3d,$d7,$fe,$62,$7e,$42,$e3,
                                 $9e,$48,$b0,$fe,$8c,$7f,$1e,$85,
                                 $f2,$db,$d5,$2c,$2d,$75,$35,$72);
begin
  writeln('Test case 7:');

  hmac_keccak_init(ctx, 224, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-224: ', compmem(@mac, @d224, sizeof(d224)));

  hmac_keccak_init(ctx, 256, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-256: ', compmem(@mac, @d256, sizeof(d256)));

  hmac_keccak_init(ctx, 384, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-384: ', compmem(@mac, @d384, sizeof(d384)));

  hmac_keccak_init(ctx, 512, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-512: ', compmem(@mac, @d512, sizeof(d512)));

end;


{---------------------------------------------------------------------------}
procedure test_case_7a;
const
  key : array[0..146] of byte = ($aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa,$aa,$aa,$aa,$aa,$aa,
                                 $aa,$aa,$aa);
  data: array[0..151] of byte = ($54,$68,$69,$73,$20,$69,$73,$20,
                                 $61,$20,$74,$65,$73,$74,$20,$75,
                                 $73,$69,$6e,$67,$20,$61,$20,$6c,
                                 $61,$72,$67,$65,$72,$20,$74,$68,
                                 $61,$6e,$20,$62,$6c,$6f,$63,$6b,
                                 $2d,$73,$69,$7a,$65,$20,$6b,$65,
                                 $79,$20,$61,$6e,$64,$20,$61,$20,
                                 $6c,$61,$72,$67,$65,$72,$20,$74,
                                 $68,$61,$6e,$20,$62,$6c,$6f,$63,
                                 $6b,$2d,$73,$69,$7a,$65,$20,$64,
                                 $61,$74,$61,$2e,$20,$54,$68,$65,
                                 $20,$6b,$65,$79,$20,$6e,$65,$65,
                                 $64,$73,$20,$74,$6f,$20,$62,$65,
                                 $20,$68,$61,$73,$68,$65,$64,$20,
                                 $62,$65,$66,$6f,$72,$65,$20,$62,
                                 $65,$69,$6e,$67,$20,$75,$73,$65,
                                 $64,$20,$62,$79,$20,$74,$68,$65,
                                 $20,$48,$4d,$41,$43,$20,$61,$6c,
                                 $67,$6f,$72,$69,$74,$68,$6d,$2e);
  d224: array[0.. 27] of byte = ($92,$64,$94,$68,$be,$23,$6c,$3c,
                                 $72,$c1,$89,$90,$9c,$06,$3b,$13,
                                 $f9,$94,$be,$05,$74,$9d,$c9,$13,
                                 $10,$db,$63,$9e);
  d256: array[0.. 31] of byte = ($fd,$aa,$10,$a0,$29,$9a,$ec,$ff,
                                 $9b,$b4,$11,$cf,$2d,$77,$48,$a4,
                                 $02,$2e,$4a,$26,$be,$3f,$b5,$b1,
                                 $1b,$33,$d8,$c2,$b7,$ef,$54,$84);
  d384: array[0.. 47] of byte = ($fe,$93,$57,$e3,$cf,$a5,$38,$eb,
                                 $03,$73,$a2,$ce,$8f,$1e,$26,$ad,
                                 $65,$90,$af,$da,$f2,$66,$f1,$30,
                                 $05,$22,$e8,$89,$6d,$27,$e7,$3f,
                                 $65,$4d,$06,$31,$c8,$fa,$59,$8d,
                                 $4b,$b8,$2a,$f6,$b7,$44,$f4,$f5);
  d512: array[0.. 63] of byte = ($6a,$dc,$50,$2f,$14,$e2,$78,$12,
                                 $40,$2f,$c8,$1a,$80,$7b,$28,$bf,
                                 $8a,$53,$c8,$7b,$ea,$7a,$1d,$f6,
                                 $25,$6b,$f6,$6f,$5d,$e1,$a4,$cb,
                                 $74,$14,$07,$ad,$15,$ab,$8a,$bc,
                                 $13,$68,$46,$05,$7f,$88,$19,$69,
                                 $fb,$b1,$59,$c3,$21,$c9,$04,$bf,
                                 $b5,$57,$b7,$7a,$fb,$77,$78,$c8);
begin
  writeln('Test case 7a:');

  hmac_keccak_init(ctx, 224, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-224: ', compmem(@mac, @d224, sizeof(d224)));

  hmac_keccak_init(ctx, 256, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-256: ', compmem(@mac, @d256, sizeof(d256)));

  hmac_keccak_init(ctx, 384, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-384: ', compmem(@mac, @d384, sizeof(d384)));

  hmac_keccak_init(ctx, 512, @key, sizeof(key));
  hmac_keccak_update(ctx, @data, sizeof(data));
  hmac_keccak_final(ctx, mac);
  writeln('  HMAC-Keccak-512: ', compmem(@mac, @d512, sizeof(d512)));

end;



begin
  writeln('HMAC-Keccak tests using David Ireland''s "Test vectors for HMAC-SHA-3"');
  test_case_1;
  test_case_2;
  test_case_3;
  test_case_4;
  test_case_5;
  test_case_6;
  test_case_6a;
  test_case_7;
  test_case_7a;
end.
