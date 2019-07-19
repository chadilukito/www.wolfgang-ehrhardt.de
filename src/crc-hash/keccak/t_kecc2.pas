program t_kecc2;

{Keccak test program with message length 2111 bits}

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}


uses
  {$ifdef WINCRT} WinCRT, {$endif}
  BTypes, Mem_Util, keccak_n;

const
  m2111: array[0..263] of byte = ($91,$9f,$e5,$e7,$f3,$5f,$64,$a7,
                                  $48,$76,$49,$e5,$64,$77,$1d,$bb,
                                  $f1,$0a,$e2,$04,$ec,$c2,$18,$13,
                                  $12,$d1,$a7,$9f,$b5,$79,$29,$7c,
                                  $94,$f0,$db,$9e,$aa,$e9,$e0,$09,
                                  $a4,$f0,$20,$57,$af,$2c,$97,$3c,
                                  $5d,$af,$a7,$b6,$01,$54,$37,$1a,
                                  $5d,$2c,$8e,$99,$2f,$b6,$42,$91,
                                  $76,$f8,$42,$4b,$1a,$86,$6b,$c1,
                                  $d1,$be,$d0,$04,$38,$e9,$7f,$ab,
                                  $42,$04,$0d,$ca,$cd,$ef,$7c,$a9,
                                  $fc,$20,$33,$05,$9b,$88,$98,$bb,
                                  $40,$cc,$fb,$26,$34,$b0,$51,$79,
                                  $7b,$df,$3b,$91,$5c,$50,$3e,$c8,
                                  $18,$39,$ad,$01,$e0,$f4,$f2,$f8,
                                  $71,$ef,$f2,$00,$8d,$40,$01,$17,
                                  $30,$be,$7a,$47,$88,$8e,$79,$55,
                                  $a8,$06,$87,$6b,$e1,$20,$cb,$0f,
                                  $3a,$13,$9a,$36,$20,$15,$4e,$cc,
                                  $64,$82,$a7,$0f,$56,$29,$f6,$a9,
                                  $d3,$34,$1b,$e6,$fb,$bf,$48,$e5,
                                  $aa,$0c,$53,$58,$9a,$04,$f0,$57,
                                  $dd,$44,$26,$8a,$ff,$ca,$bf,$75,
                                  $ad,$fc,$54,$9f,$73,$f4,$54,$26,
                                  $4d,$46,$a9,$8c,$ca,$80,$e3,$00,
                                  $0c,$74,$46,$85,$3d,$d5,$b4,$30,
                                  $c9,$34,$4e,$87,$e3,$23,$05,$55,
                                  $b0,$9f,$b3,$e7,$e6,$4b,$5a,$d3,
                                  $98,$92,$93,$ac,$0f,$ee,$c0,$e7,
                                  $5f,$90,$96,$96,$f0,$28,$a5,$52,
                                  $5d,$26,$dd,$ea,$5d,$2b,$2c,$81,
                                  $3f,$b3,$61,$3d,$ff,$38,$ce,$23,
                                  $20,$92,$85,$cc,$77,$c6,$08,$60);

    dsq: array[0..511] of byte = ($18,$0d,$20,$4f,$97,$d2,$70,$d3,
                                  $67,$a1,$d4,$e9,$80,$81,$46,$f6,
                                  $d9,$46,$bd,$05,$a8,$7a,$58,$09,
                                  $50,$8e,$2b,$c3,$e8,$84,$8d,$47,
                                  $c8,$51,$01,$5f,$97,$9e,$e3,$f0,
                                  $7e,$88,$e2,$bf,$32,$0f,$84,$01,
                                  $4f,$92,$47,$af,$0e,$d3,$13,$06,
                                  $64,$43,$4f,$47,$c1,$fa,$1e,$d5,
                                  $7a,$fa,$6a,$3d,$99,$fd,$34,$0d,
                                  $c7,$02,$77,$ef,$cc,$05,$4a,$98,
                                  $09,$b6,$fa,$36,$ae,$61,$bf,$43,
                                  $a7,$74,$74,$ab,$74,$3c,$e9,$8d,
                                  $a5,$e1,$57,$2d,$e2,$c1,$46,$2e,
                                  $1d,$0a,$b4,$2d,$61,$4a,$ee,$89,
                                  $99,$5c,$05,$c3,$c5,$a5,$fe,$fc,
                                  $10,$86,$81,$98,$91,$16,$1e,$7a,
                                  $ea,$1a,$c5,$71,$c3,$1c,$57,$75,
                                  $7d,$67,$ca,$0c,$4e,$c4,$2f,$40,
                                  $5f,$79,$ba,$44,$72,$ff,$3f,$cb,
                                  $8f,$00,$9c,$b1,$9c,$cb,$84,$03,
                                  $43,$76,$35,$78,$1e,$cc,$31,$c4,
                                  $7f,$dd,$99,$c1,$c3,$66,$cf,$1b,
                                  $4c,$d2,$c0,$6d,$e2,$f6,$41,$ec,
                                  $85,$49,$d7,$d2,$78,$fe,$e6,$36,
                                  $62,$60,$ef,$de,$c4,$76,$e8,$a2,
                                  $59,$37,$ea,$e2,$74,$4c,$63,$15,
                                  $b0,$ca,$04,$2b,$4b,$bd,$84,$05,
                                  $a7,$83,$26,$99,$b3,$d1,$05,$c3,
                                  $a8,$54,$8d,$48,$43,$93,$35,$07,
                                  $59,$25,$51,$a1,$45,$e2,$77,$4d,
                                  $45,$c7,$9b,$db,$70,$68,$7e,$8c,
                                  $78,$82,$6c,$68,$e8,$44,$ea,$d7,
                                  $a8,$d8,$08,$92,$4e,$b4,$a3,$50,
                                  $ff,$25,$70,$86,$48,$d3,$7a,$1e,
                                  $b3,$70,$2b,$07,$55,$95,$5f,$a0,
                                  $0a,$fe,$bd,$6f,$58,$25,$55,$9f,
                                  $47,$4f,$8f,$4e,$83,$c9,$d4,$99,
                                  $89,$5c,$11,$6d,$3f,$b0,$95,$64,
                                  $69,$aa,$00,$00,$a8,$24,$70,$53,
                                  $82,$c2,$90,$02,$8e,$b9,$c8,$06,
                                  $e5,$04,$1f,$98,$d1,$14,$6c,$4f,
                                  $b6,$28,$4a,$73,$31,$46,$97,$9a,
                                  $2f,$fc,$39,$7f,$72,$e6,$04,$8c,
                                  $65,$35,$41,$05,$4b,$5a,$66,$06,
                                  $3d,$15,$3b,$6e,$90,$15,$7e,$8c,
                                  $fd,$79,$1a,$f8,$43,$5a,$d4,$23,
                                  $02,$93,$1c,$e2,$58,$aa,$c6,$4e,
                                  $a9,$ea,$b3,$4e,$bb,$d7,$65,$a6,
                                  $3e,$ef,$5b,$e8,$59,$66,$96,$40,
                                  $ff,$37,$13,$db,$a7,$67,$6f,$ff,
                                  $d1,$a8,$3a,$5b,$28,$71,$d3,$be,
                                  $35,$c9,$73,$82,$ae,$6a,$a8,$24,
                                  $3a,$43,$97,$f1,$87,$f4,$75,$b1,
                                  $cc,$56,$dd,$6d,$61,$7b,$8a,$79,
                                  $8c,$4f,$38,$67,$ec,$a5,$b3,$d6,
                                  $12,$ae,$c9,$b7,$32,$7c,$be,$58,
                                  $bb,$1f,$d2,$7d,$ec,$5f,$55,$74,
                                  $6d,$06,$fe,$05,$72,$2c,$6f,$a5,
                                  $20,$ec,$5b,$48,$00,$ad,$e6,$27,
                                  $a1,$df,$74,$d9,$d1,$f2,$4c,$85,
                                  $a8,$a0,$c5,$b3,$fe,$91,$bd,$4a,
                                  $3a,$da,$62,$56,$78,$63,$fd,$34,
                                  $58,$b0,$28,$fe,$b3,$ae,$3e,$08,
                                  $ca,$e4,$4e,$08,$0d,$9a,$84,$3d);

  d224 : array[0.. 27] of byte = ($0a,$98,$3f,$18,$24,$1d,$c9,$64,
                                  $8b,$c4,$04,$f6,$ef,$ae,$ac,$20,
                                  $ad,$81,$ff,$38,$25,$f3,$8f,$06,
                                  $9a,$64,$12,$4c);

  d256 : array[0.. 31] of byte = ($6d,$0c,$e2,$d2,$e3,$af,$33,$03,
                                  $36,$16,$e3,$84,$dc,$a4,$d4,$4d,
                                  $74,$2f,$f7,$fe,$fa,$4f,$f2,$c4,
                                  $2e,$e9,$f1,$c3,$38,$e8,$9c,$dd);

  d384 : array[0.. 47] of byte = ($21,$02,$45,$79,$e9,$ba,$29,$6f,
                                  $b4,$2e,$33,$07,$48,$a8,$1e,$a6,
                                  $16,$11,$e1,$1e,$1f,$fb,$1f,$6d,
                                  $4c,$ab,$2d,$2d,$5d,$c2,$4e,$c8,
                                  $10,$fd,$d3,$6a,$e6,$a2,$8b,$ed,
                                  $d9,$6a,$40,$fc,$69,$d6,$c1,$25);

  d512 : array[0.. 63] of byte = ($4a,$1b,$83,$f2,$69,$25,$1d,$71,
                                  $e1,$b4,$d6,$55,$33,$79,$59,$92,
                                  $cb,$e4,$f2,$50,$1a,$e8,$49,$01,
                                  $f4,$1e,$93,$25,$49,$2f,$96,$2f,
                                  $a9,$5d,$49,$d8,$67,$6b,$01,$7f,
                                  $c7,$c3,$71,$17,$75,$ec,$de,$ea,
                                  $8b,$22,$e0,$d7,$dd,$a6,$7b,$c9,
                                  $26,$b8,$3d,$9d,$c4,$25,$ce,$30);

var
  i: integer;
  state: thashState;
  buf: array[0..1023] of byte;
begin
  writeln('----------------------');
  writeln('Process 2111 bit message');
  writeln;

  writeln('Squeeze 512 bytes');
  i := Init(state,0);
  writeln('   Init = ',i);
  i := Update(state, @m2111, 2111);
  writeln(' Update = ',i);
  i := Squeeze(state,@buf,512*8);
  writeln('Squeeze = ',i);
  writeln(' Passed = ',compmem(@buf, @dsq, sizeof(dsq)));

  writeln;
  writeln('Keccak 224');
  i := Init(state,224);
  writeln('   Init = ',i);
  i := Update(state, @m2111, 2111);
  writeln(' Update = ',i);
  i := Final(state,@buf);
  writeln('  Final = ',i);
  writeln(' Passed = ',compmem(@buf, @d224, sizeof(d224)));

  writeln;
  writeln('Keccak 256');
  i := Init(state,256);
  writeln('   Init = ',i);
  i := Update(state, @m2111, 2111);
  writeln(' Update = ',i);
  i := Final(state,@buf);
  writeln('  Final = ',i);
  writeln(' Passed = ',compmem(@buf, @d256, sizeof(d256)));

  writeln;
  writeln('Keccak 384');
  i := Init(state,384);
  writeln('   Init = ',i);
  i := Update(state, @m2111, 2111);
  writeln(' Update = ',i);
  i := Final(state,@buf);
  writeln('  Final = ',i);
  writeln(' Passed = ',compmem(@buf, @d384, sizeof(d384)));

  writeln;
  writeln('Keccak 512');
  i := Init(state,512);
  writeln('   Init = ',i);
  i := Update(state, @m2111, 2111);
  writeln(' Update = ',i);
  i := Final(state,@buf);
  writeln('  Final = ',i);
  writeln(' Passed = ',compmem(@buf, @d512, sizeof(d512)));


end.

