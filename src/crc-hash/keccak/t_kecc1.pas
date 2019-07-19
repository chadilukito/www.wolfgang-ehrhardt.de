program t_kecc1;

{Historically my first test program with byte size messages}
{rewritten for usage with keccak_n}

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}


uses
  {$ifdef WINCRT} WinCRT, {$endif}
  BTypes, Mem_Util, keccak_n;


{---------------------------------------------------------------------------}
function crypto_hash(outp: pointer; inp: pointer; inlen: longint): integer;
  {-Hash input with HashBitlen=0 (rate=1024), squeeze 128 bytes into outp)}
var
  state: thashState;
  i: integer;
begin
  i := Init(state,0);
  if i<>0 then begin
    crypto_hash := i;
    exit;
  end;
  i := Update(state, inp, inlen*8);
  if i<>0 then begin
    crypto_hash := i;
    exit;
  end;
  crypto_hash := Squeeze(state, outp, 128*8);
end;


{---------------------------------------------------------------------------}
{From  ShortMsgKAT_0.txt}
const msg0: array[0..0] of byte = ($00);

const res0: array[0..127] of byte = ($67,$53,$e3,$38,$0c,$09,$e3,$85,
                                 $d0,$33,$9e,$b6,$b0,$50,$a6,$8f,
                                 $66,$cf,$d6,$0a,$73,$47,$6e,$6f,
                                 $d6,$ad,$eb,$72,$f5,$ed,$d7,$c6,
                                 $f0,$4a,$5d,$01,$7a,$19,$cb,$e2,
                                 $91,$93,$58,$55,$b4,$86,$0f,$69,
                                 $df,$04,$c9,$8a,$a7,$8b,$40,$7a,
                                 $9b,$a9,$82,$6f,$72,$66,$ef,$14,
                                 $ba,$6d,$3f,$90,$c4,$fe,$15,$4d,
                                 $27,$c2,$85,$8e,$a6,$db,$8c,$11,
                                 $74,$11,$a1,$bc,$5c,$49,$94,$10,
                                 $c3,$91,$b2,$98,$f3,$7b,$f6,$36,
                                 $b0,$f5,$c3,$1d,$bd,$64,$87,$a7,
                                 $d3,$d8,$cf,$2a,$97,$b6,$19,$69,
                                 $7e,$66,$d8,$94,$29,$9b,$8b,$4d,
                                 $80,$e0,$49,$85,$38,$e1,$85,$44);

const msg1: array[0..0] of byte = ($cc);

const res1: array[0..127] of byte = ($56,$b9,$70,$29,$b4,$79,$ff,$5d,
                                 $d1,$5f,$17,$d1,$29,$83,$e3,$b8,
                                 $35,$bb,$05,$31,$d9,$b8,$d4,$9b,
                                 $10,$3b,$02,$5c,$a5,$3f,$99,$17,
                                 $41,$29,$8e,$96,$1d,$1f,$ad,$00,
                                 $fc,$36,$5c,$77,$61,$bf,$b2,$78,
                                 $ae,$47,$39,$80,$d6,$12,$c1,$62,
                                 $9e,$07,$5a,$3f,$db,$ae,$7f,$82,
                                 $b0,$f0,$af,$54,$df,$18,$7f,$35,
                                 $88,$52,$e1,$9e,$a4,$34,$7c,$f5,
                                 $ce,$ea,$67,$6a,$1d,$ce,$3a,$47,
                                 $44,$7e,$23,$7f,$d7,$42,$04,$f9,
                                 $a4,$b7,$f7,$c9,$cc,$7c,$c8,$b8,
                                 $65,$b1,$d5,$54,$e2,$f5,$f4,$a8,
                                 $ee,$17,$db,$dd,$e7,$26,$78,$94,
                                 $55,$8a,$20,$97,$2c,$9e,$b6,$cf);

const msg2: array[0..1] of byte = ($41,$fb);

const res2: array[0..127] of byte = ($cb,$e9,$63,$38,$dd,$8f,$04,$c0,
                                 $69,$42,$99,$63,$7a,$ab,$22,$3b,
                                 $6d,$60,$56,$0c,$6b,$ed,$7f,$69,
                                 $92,$3a,$eb,$b2,$4f,$c6,$1b,$84,
                                 $70,$24,$03,$d3,$9e,$7d,$08,$1f,
                                 $7f,$7b,$71,$4e,$3b,$a6,$e6,$22,
                                 $1f,$e8,$40,$f5,$7a,$1e,$9b,$d7,
                                 $75,$b9,$0d,$59,$c9,$85,$36,$95,
                                 $c2,$b1,$1c,$d0,$6f,$10,$54,$21,
                                 $0d,$7d,$81,$55,$b9,$08,$ff,$4e,
                                 $e1,$4f,$df,$85,$9b,$6d,$5a,$a6,
                                 $bf,$76,$90,$3b,$e0,$af,$4a,$2f,
                                 $fd,$52,$b2,$b1,$49,$da,$32,$c8,
                                 $e3,$72,$f5,$18,$26,$d4,$ca,$7d,
                                 $cd,$65,$16,$d1,$67,$a0,$62,$1a,
                                 $a8,$89,$86,$d1,$9a,$52,$4d,$d3);

const msg3: array[0..19] of byte = ($e2,$61,$93,$98,$9d,$06,$56,$8f,
                                 $e6,$88,$e7,$55,$40,$ae,$a0,$67,
                                 $47,$d9,$f8,$51);

const res3: array[0..127] of byte = ($84,$67,$44,$04,$e7,$6d,$25,$87,
                                 $da,$28,$3e,$93,$6e,$9b,$60,$e7,
                                 $af,$9a,$c5,$55,$a3,$40,$07,$7e,
                                 $64,$19,$7a,$70,$d5,$a6,$e5,$7f,
                                 $fe,$04,$93,$d7,$80,$58,$95,$b8,
                                 $d8,$98,$3a,$1f,$d9,$e6,$65,$85,
                                 $a0,$10,$58,$46,$ca,$dd,$6d,$dd,
                                 $de,$43,$4c,$89,$1e,$28,$17,$74,
                                 $56,$88,$fb,$02,$f2,$87,$f7,$ae,
                                 $7e,$1e,$e1,$42,$ad,$64,$fd,$64,
                                 $4e,$72,$fd,$dc,$92,$07,$a9,$8b,
                                 $c2,$f5,$47,$d4,$34,$c0,$bc,$f6,
                                 $73,$a9,$02,$19,$d8,$b2,$15,$53,
                                 $08,$99,$16,$83,$7a,$9a,$da,$86,
                                 $f7,$ed,$1e,$55,$e0,$0c,$33,$dc,
                                 $4a,$98,$0c,$52,$8f,$e7,$08,$c1);

const msg4: array[0.. 31] of byte = ($9f,$2f,$cc,$7c,$90,$de,$09,$0d,
                                 $6b,$87,$cd,$7e,$97,$18,$c1,$ea,
                                 $6c,$b2,$11,$18,$fc,$2d,$5d,$e9,
                                 $f9,$7e,$5d,$b6,$ac,$1e,$9c,$10);

const res4: array[0..127] of byte = ($2a,$24,$f9,$6d,$9f,$5f,$c4,$7c,
                                 $f4,$b7,$cf,$4d,$d1,$36,$96,$8b,
                                 $84,$05,$14,$74,$ee,$f7,$e3,$e1,
                                 $8d,$18,$b5,$21,$bf,$90,$2a,$4e,
                                 $9b,$d4,$b8,$eb,$57,$4b,$4d,$44,
                                 $1b,$72,$aa,$f7,$99,$00,$76,$22,
                                 $8e,$ad,$05,$25,$07,$b6,$c8,$8e,
                                 $29,$8f,$dd,$e0,$e3,$0b,$c1,$a9,
                                 $48,$0b,$d8,$a7,$8f,$34,$4d,$b4,
                                 $a8,$52,$0b,$94,$0b,$ae,$c3,$25,
                                 $a5,$77,$83,$70,$82,$5e,$ee,$1f,
                                 $b0,$94,$36,$fa,$f2,$c6,$7b,$a6,
                                 $b9,$4b,$34,$1b,$ed,$52,$33,$57,
                                 $18,$d0,$b9,$f7,$af,$f7,$78,$27,
                                 $e4,$cf,$59,$8d,$bc,$57,$22,$ae,
                                 $9a,$1d,$43,$33,$fa,$61,$d6,$f7);


const msg5: array[0..126] of byte = ($a6,$2f,$c5,$95,$b4,$09,$6e,$63,
                                 $36,$e5,$3f,$cd,$fc,$8d,$1c,$c1,
                                 $75,$d7,$1d,$ac,$9d,$75,$0a,$61,
                                 $33,$d2,$31,$99,$ea,$ac,$28,$82,
                                 $07,$94,$4c,$ea,$6b,$16,$d2,$76,
                                 $31,$91,$5b,$46,$19,$f7,$43,$da,
                                 $2e,$30,$a0,$c0,$0b,$bd,$b1,$bb,
                                 $b3,$5a,$b8,$52,$ef,$3b,$9a,$ec,
                                 $6b,$0a,$8d,$cc,$6e,$9e,$1a,$ba,
                                 $a3,$ad,$62,$ac,$0a,$6c,$5d,$e7,
                                 $65,$de,$2c,$37,$11,$b7,$69,$e3,
                                 $fd,$e4,$4a,$74,$01,$6f,$ff,$82,
                                 $ac,$46,$fa,$8f,$17,$97,$d3,$b2,
                                 $a7,$26,$b6,$96,$e3,$de,$a5,$53,
                                 $04,$39,$ac,$ee,$3a,$45,$c2,$a5,
                                 $1b,$c3,$2d,$d0,$55,$65,$0b);

const res5: array[0..127] of byte = ($85,$f9,$7b,$68,$a9,$43,$6d,$ba,
                                 $0e,$b0,$5d,$d2,$a8,$5a,$d0,$9a,
                                 $c9,$f5,$6b,$78,$93,$36,$7a,$95,
                                 $42,$91,$e2,$21,$d5,$ed,$ec,$3a,
                                 $3c,$c9,$f3,$91,$d2,$95,$a3,$40,
                                 $e6,$31,$ce,$14,$fc,$7a,$1f,$fb,
                                 $bc,$17,$3a,$9b,$bb,$28,$84,$b9,
                                 $83,$a9,$ca,$4c,$46,$76,$1e,$74,
                                 $e3,$d4,$cd,$d0,$54,$fe,$6d,$3f,
                                 $73,$f0,$6c,$40,$ec,$fb,$24,$1e,
                                 $f9,$a6,$da,$5c,$b0,$0d,$e4,$22,
                                 $5b,$2b,$e2,$d9,$22,$a3,$b9,$fb,
                                 $8a,$23,$e0,$1d,$ca,$19,$b6,$95,
                                 $0f,$ed,$be,$82,$82,$42,$9a,$33,
                                 $09,$da,$09,$7a,$fb,$f3,$3c,$09,
                                 $56,$37,$fe,$9a,$ca,$e0,$10,$f1);


const msg6: array[0..127] of byte = ($2b,$6d,$b7,$ce,$d8,$66,$5e,$be,
                                 $9d,$eb,$08,$02,$95,$21,$84,$26,
                                 $bd,$aa,$7c,$6d,$a9,$ad,$d2,$08,
                                 $89,$32,$cd,$ff,$ba,$a1,$c1,$41,
                                 $29,$bc,$cd,$d7,$0f,$36,$9e,$fb,
                                 $14,$92,$85,$85,$8d,$2b,$1d,$15,
                                 $5d,$14,$de,$2f,$db,$68,$0a,$8b,
                                 $02,$72,$84,$05,$51,$82,$a0,$ca,
                                 $e2,$75,$23,$4c,$c9,$c9,$28,$63,
                                 $c1,$b4,$ab,$66,$f3,$04,$cf,$06,
                                 $21,$cd,$54,$56,$5f,$5b,$ff,$46,
                                 $1d,$3b,$46,$1b,$d4,$0d,$f2,$81,
                                 $98,$e3,$73,$25,$01,$b4,$86,$0e,
                                 $ad,$d5,$03,$d2,$6d,$6e,$69,$33,
                                 $8f,$4e,$04,$56,$e9,$e9,$ba,$f3,
                                 $d8,$27,$ae,$68,$5f,$b1,$d8,$17);

const res6: array[0..127] of byte = ($dc,$ac,$84,$56,$8f,$15,$ca,$c0,
                                 $76,$85,$4e,$a6,$92,$de,$95,$e4,
                                 $73,$76,$8a,$99,$df,$9a,$c2,$32,
                                 $8e,$e4,$23,$d0,$2e,$eb,$8e,$e8,
                                 $e1,$d1,$70,$62,$13,$c4,$41,$5d,
                                 $c7,$aa,$fa,$66,$47,$6d,$8e,$bd,
                                 $dd,$d8,$bf,$39,$e1,$de,$05,$ca,
                                 $76,$c3,$6e,$7e,$97,$56,$29,$33,
                                 $1f,$3a,$33,$c3,$ca,$40,$91,$c8,
                                 $20,$04,$e5,$89,$1b,$7e,$27,$6d,
                                 $46,$42,$ea,$61,$bd,$e0,$21,$87,
                                 $1c,$9b,$5c,$8c,$fa,$82,$14,$4b,
                                 $7a,$41,$44,$b4,$4e,$be,$60,$93,
                                 $e9,$5c,$59,$30,$5f,$d3,$6a,$87,
                                 $41,$c4,$f2,$df,$65,$cb,$0b,$59,
                                 $f8,$03,$cf,$dc,$f2,$ce,$4b,$8b);


const msg7: array[0..136] of byte = ($04,$41,$0e,$31,$08,$2a,$47,$58,
                                 $4b,$40,$6f,$05,$13,$98,$a6,$ab,
                                 $e7,$4e,$4d,$a5,$9b,$b6,$f8,$5e,
                                 $6b,$49,$e8,$a1,$f7,$f2,$ca,$00,
                                 $df,$ba,$54,$62,$c2,$cd,$2b,$fd,
                                 $e8,$b6,$4f,$b2,$1d,$70,$c0,$83,
                                 $f1,$13,$18,$b5,$6a,$52,$d0,$3b,
                                 $81,$ca,$c5,$ee,$c2,$9e,$b3,$1b,
                                 $d0,$07,$8b,$61,$56,$78,$6d,$a3,
                                 $d6,$d8,$c3,$30,$98,$c5,$c4,$7b,
                                 $b6,$7a,$c6,$4d,$b1,$41,$65,$af,
                                 $65,$b4,$45,$44,$d8,$06,$dd,$e5,
                                 $f4,$87,$d5,$37,$3c,$7f,$97,$92,
                                 $c2,$99,$e9,$68,$6b,$7e,$58,$21,
                                 $e7,$c8,$e2,$45,$83,$15,$b9,$96,
                                 $b5,$67,$7d,$92,$6d,$ac,$57,$b3,
                                 $f2,$2d,$a8,$73,$c6,$01,$01,$6a,
                                 $0d);

const res7: array[0..127] of byte = ($ee,$3f,$96,$61,$65,$52,$bb,$63,
                                 $58,$2a,$9b,$d4,$d9,$07,$46,$3b,
                                 $d2,$e5,$1a,$f4,$bc,$b8,$ca,$46,
                                 $f5,$1e,$fb,$f2,$2e,$59,$f6,$83,
                                 $98,$8c,$36,$30,$8c,$a7,$e7,$19,
                                 $3a,$16,$dd,$70,$c4,$3d,$08,$fc,
                                 $a8,$be,$de,$b6,$32,$02,$e9,$c2,
                                 $de,$8b,$41,$77,$a9,$af,$75,$5d,
                                 $b5,$dc,$c7,$6c,$a1,$8a,$bb,$34,
                                 $f8,$57,$55,$df,$b4,$49,$3d,$6d,
                                 $52,$16,$49,$3c,$13,$a1,$e5,$b3,
                                 $9f,$f7,$d5,$80,$36,$72,$83,$40,
                                 $33,$1d,$da,$48,$e7,$ee,$8a,$70,
                                 $1c,$0a,$fb,$e8,$c7,$46,$a3,$40,
                                 $1d,$87,$9c,$97,$f7,$1e,$80,$b5,
                                 $6e,$fb,$e8,$2b,$50,$ff,$09,$45);


const msg8: array[0..318] of byte = ($31,$39,$84,$0b,$8a,$d4,$bc,$d3,
                                 $90,$92,$91,$6f,$d9,$d0,$17,$98,
                                 $ff,$5a,$a1,$e4,$8f,$34,$70,$2c,
                                 $72,$df,$e7,$4b,$12,$e9,$8a,$11,
                                 $4e,$31,$8c,$dd,$2d,$47,$a9,$c3,
                                 $20,$ff,$f9,$08,$a8,$db,$c2,$a5,
                                 $b1,$d8,$72,$67,$c8,$e9,$83,$82,
                                 $98,$61,$a5,$67,$55,$8b,$37,$b2,
                                 $92,$d4,$57,$5e,$20,$0d,$e9,$f1,
                                 $de,$45,$75,$5f,$af,$f9,$ef,$ae,
                                 $34,$96,$4e,$43,$36,$c2,$59,$f1,
                                 $e6,$65,$99,$a7,$c9,$04,$ec,$02,
                                 $53,$9f,$1a,$8e,$ab,$87,$06,$e0,
                                 $b4,$f4,$8f,$72,$fe,$c2,$79,$49,
                                 $09,$ee,$4a,$7b,$09,$2d,$60,$61,
                                 $c7,$44,$81,$c9,$e2,$1b,$93,$32,
                                 $dc,$7c,$6e,$48,$2d,$7f,$9c,$c3,
                                 $21,$0b,$38,$a6,$f8,$8f,$79,$18,
                                 $c2,$d8,$c5,$5e,$64,$a4,$28,$ce,
                                 $2b,$68,$fd,$07,$ab,$57,$2a,$8b,
                                 $0a,$23,$88,$66,$4f,$99,$48,$9f,
                                 $04,$eb,$54,$df,$13,$76,$27,$18,
                                 $10,$e0,$e7,$bc,$e3,$96,$f5,$28,
                                 $07,$71,$0e,$0d,$ea,$94,$eb,$49,
                                 $f4,$b3,$67,$27,$12,$60,$c3,$45,
                                 $6b,$98,$18,$fc,$7a,$72,$23,$4e,
                                 $6b,$f2,$20,$5f,$f6,$a3,$65,$46,
                                 $20,$50,$15,$eb,$d7,$d8,$c2,$52,
                                 $7a,$a4,$30,$f5,$8e,$0e,$8a,$c9,
                                 $7a,$7b,$6b,$79,$3c,$d4,$03,$d5,
                                 $17,$d6,$62,$95,$f3,$7a,$34,$d0,
                                 $b7,$d2,$fa,$7b,$c3,$45,$ac,$04,
                                 $ca,$1e,$26,$64,$80,$de,$ec,$39,
                                 $f5,$c8,$86,$41,$c9,$dc,$0b,$d1,
                                 $35,$81,$58,$fd,$ec,$dd,$96,$68,
                                 $5b,$bb,$b5,$c1,$fe,$5e,$a8,$9d,
                                 $2c,$b4,$a9,$d5,$d1,$2b,$b8,$c8,
                                 $93,$28,$1f,$f3,$8e,$87,$d6,$b4,
                                 $84,$1f,$06,$50,$09,$2d,$44,$7e,
                                 $01,$3f,$20,$ea,$93,$4e,$18);

const res8: array[0..127] of byte = ($ef,$e3,$48,$28,$37,$cf,$b4,$00,
                                 $61,$c5,$42,$3f,$75,$7f,$8f,$ff,
                                 $aa,$ed,$7a,$73,$e8,$a7,$15,$c6,
                                 $4c,$e2,$0c,$b3,$a4,$47,$3e,$7c,
                                 $6d,$df,$7d,$ab,$e1,$b0,$bf,$b2,
                                 $3c,$5c,$54,$73,$64,$b8,$3e,$e3,
                                 $aa,$0b,$56,$c5,$f3,$66,$b9,$f0,
                                 $37,$f8,$64,$e5,$b7,$57,$83,$5d,
                                 $d9,$6f,$c4,$0f,$0f,$4b,$e0,$e3,
                                 $56,$e7,$d7,$74,$99,$41,$30,$e4,
                                 $f4,$b5,$40,$a4,$4a,$45,$79,$66,
                                 $1e,$3f,$89,$bf,$2b,$a2,$46,$c6,
                                 $fd,$4b,$9a,$c7,$91,$3b,$fa,$7f,
                                 $a2,$5c,$ec,$98,$be,$03,$69,$85,
                                 $a5,$9f,$40,$2a,$59,$1e,$e5,$86,
                                 $00,$ff,$88,$3e,$5b,$b7,$60,$2f);

var
  dig: array[0..127] of byte;
  i: integer;
begin
  writeln('----------------------');
  HexUpper := true;

  i := crypto_hash(@dig, @msg0, 0);
  write('Test 0: ');
  if i<>0 then writeln('error ',i)
  else writeln(compmem(@dig, @res0, sizeof(dig)));

  i := crypto_hash(@dig, @msg1, sizeof(msg1));
  write('Test 1: ');
  if i<>0 then writeln('error ',i)
  else writeln(compmem(@dig, @res1, sizeof(dig)));

  i := crypto_hash(@dig, @msg2, sizeof(msg2));
  write('Test 2: ');
  if i<>0 then writeln('error ',i)
  else writeln(compmem(@dig, @res2, sizeof(dig)));

  i := crypto_hash(@dig, @msg3, sizeof(msg3));
  write('Test 3: ');
  if i<>0 then writeln('error ',i)
  else writeln(compmem(@dig, @res3, sizeof(dig)));

  i := crypto_hash(@dig, @msg4, sizeof(msg4));
  write('Test 4: ');
  if i<>0 then writeln('error ',i)
  else writeln(compmem(@dig, @res4, sizeof(dig)));

  i := crypto_hash(@dig, @msg5, sizeof(msg5));
  write('Test 5: ');
  if i<>0 then writeln('error ',i)
  else writeln(compmem(@dig, @res5, sizeof(dig)));

  i := crypto_hash(@dig, @msg6, sizeof(msg6));
  write('Test 6: ');
  if i<>0 then writeln('error ',i)
  else writeln(compmem(@dig, @res6, sizeof(dig)));

  i := crypto_hash(@dig, @msg7, sizeof(msg7));
  write('Test 7: ');
  if i<>0 then writeln('error ',i)
  else writeln(compmem(@dig, @res7, sizeof(dig)));

  i := crypto_hash(@dig, @msg8, sizeof(msg8));
  write('Test 8: ');
  if i<>0 then writeln('error ',i)
  else writeln(compmem(@dig, @res8, sizeof(dig)));

end.

