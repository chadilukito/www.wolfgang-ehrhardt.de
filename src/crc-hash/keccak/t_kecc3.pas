program t_kecc3;

{Hash 1GB of data with Keccak-512, Ref: ExtremelyLongMsgKAT_0.txt}

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}


uses
  {$ifdef WINCRT} WinCRT, {$endif}
  BTypes, Mem_Util, keccak_n;


const
  msg : array[0..63] of char8 = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno';
  REP = 16777216;

const
(*
  d224 : array[0..27] of byte = ($c4,$2e,$4a,$ee,$85,$8e,$1a,$8a,
                                 $d2,$97,$68,$96,$b9,$d2,$3d,$d1,
                                 $87,$f6,$44,$36,$ee,$15,$96,$9a,
                                 $fd,$bc,$68,$c5);

  d256 : array[0..31] of byte = ($5f,$31,$3c,$39,$96,$3d,$cf,$79,
                                 $2b,$54,$70,$d4,$ad,$e9,$f3,$a3,
                                 $56,$a3,$e4,$02,$17,$48,$69,$0a,
                                 $95,$83,$72,$e2,$b0,$6f,$82,$a4);

  d384 : array[0..47] of byte = ($9b,$71,$68,$b4,$49,$4a,$80,$a8,
                                 $64,$08,$e6,$b9,$dc,$4e,$5a,$18,
                                 $37,$c8,$5d,$d8,$ff,$45,$2e,$d4,
                                 $10,$f2,$83,$29,$59,$c0,$8c,$8c,
                                 $0d,$04,$0a,$89,$2e,$b9,$a7,$55,
                                 $77,$63,$72,$d4,$a8,$73,$23,$15);
*)
  d512 : array[0..63] of byte = ($3e,$12,$2e,$da,$f3,$73,$98,$23,
                                 $1c,$fa,$ca,$4c,$7c,$21,$6c,$9d,
                                 $66,$d5,$b8,$99,$ec,$1d,$7a,$c6,
                                 $17,$c4,$0c,$72,$61,$90,$6a,$45,
                                 $fc,$01,$61,$7a,$02,$1e,$5d,$a3,
                                 $bd,$8d,$41,$82,$69,$5b,$5c,$b7,
                                 $85,$a2,$82,$37,$cb,$b1,$67,$59,
                                 $0e,$34,$71,$8e,$56,$d8,$aa,$b8);
(*
  dsq : array[0..511] of byte = ($ea,$da,$f5,$ba,$2a,$d6,$a2,$f6,
                                 $f3,$38,$fc,$e0,$e1,$ef,$da,$d2,
                                 $a6,$1b,$b3,$8f,$6b,$e6,$06,$8b,
                                 $01,$09,$39,$77,$ac,$f9,$9e,$97,
                                 $a5,$d5,$82,$7c,$27,$29,$c5,$0d,
                                 $88,$54,$fa,$39,$98,$a5,$2d,$ed,
                                 $e1,$6c,$59,$00,$64,$a4,$30,$de,
                                 $b6,$50,$a1,$a4,$55,$da,$52,$ea,
                                 $be,$9c,$d9,$36,$2b,$42,$40,$0e,
                                 $0d,$d9,$a3,$91,$61,$fb,$f3,$3b,
                                 $76,$01,$b2,$e0,$39,$ac,$1c,$40,
                                 $77,$e0,$94,$81,$fe,$74,$7c,$aa,
                                 $a3,$48,$07,$76,$ec,$86,$c9,$fb,
                                 $c0,$9d,$a2,$3f,$89,$be,$8b,$88,
                                 $f2,$6d,$ec,$f7,$c5,$57,$38,$49,
                                 $69,$1f,$42,$ff,$72,$58,$f5,$20,
                                 $a8,$90,$4a,$13,$1a,$3d,$0b,$8b,
                                 $de,$6d,$7d,$f5,$63,$1c,$f6,$8c,
                                 $4e,$4e,$76,$97,$6c,$cd,$34,$30,
                                 $3d,$6a,$cc,$fd,$52,$29,$eb,$83,
                                 $33,$dc,$83,$bc,$cc,$c1,$a1,$60,
                                 $2f,$a6,$08,$74,$c8,$e4,$5b,$05,
                                 $09,$9f,$59,$a5,$ae,$79,$cd,$89,
                                 $b1,$64,$35,$bf,$03,$5e,$80,$4b,
                                 $e3,$08,$70,$ad,$c4,$88,$76,$2c,
                                 $20,$d2,$a7,$6e,$45,$d4,$43,$02,
                                 $17,$62,$b5,$c5,$de,$39,$5c,$d6,
                                 $7f,$47,$aa,$06,$12,$6e,$33,$e8,
                                 $39,$5d,$d1,$55,$9c,$93,$9f,$9d,
                                 $d5,$5d,$89,$b8,$93,$78,$a4,$da,
                                 $8f,$53,$96,$1c,$c0,$f9,$e7,$d3,
                                 $0a,$70,$bf,$d5,$22,$40,$cb,$b5,
                                 $f7,$a8,$ab,$7b,$bf,$90,$39,$95,
                                 $e1,$b1,$13,$c1,$8c,$fb,$c2,$b7,
                                 $e7,$11,$6a,$1b,$0b,$2d,$e0,$3e,
                                 $b4,$c0,$c3,$5b,$cc,$2b,$0c,$9e,
                                 $a8,$41,$5f,$c3,$cc,$3e,$5c,$8b,
                                 $0f,$c6,$3b,$3c,$c2,$fb,$00,$27,
                                 $fb,$82,$79,$25,$41,$80,$67,$e0,
                                 $85,$40,$49,$83,$32,$94,$df,$d1,
                                 $64,$9f,$3e,$87,$76,$8c,$dd,$00,
                                 $0f,$ee,$68,$db,$3e,$ce,$d4,$83,
                                 $62,$4e,$12,$67,$ad,$fd,$42,$5b,
                                 $aa,$26,$16,$8c,$46,$7b,$c4,$13,
                                 $57,$f9,$5e,$7c,$50,$13,$7a,$84,
                                 $58,$44,$d6,$94,$c7,$78,$7a,$f6,
                                 $57,$69,$66,$e9,$b5,$6d,$e0,$d3,
                                 $54,$12,$7d,$b3,$2b,$12,$23,$51,
                                 $67,$52,$fa,$f0,$90,$38,$cf,$f9,
                                 $92,$da,$d0,$8a,$af,$0b,$eb,$0b,
                                 $42,$7d,$0c,$d8,$74,$d1,$c2,$db,
                                 $2c,$83,$fe,$92,$34,$ed,$05,$73,
                                 $0d,$97,$0f,$d1,$11,$9a,$ae,$f4,
                                 $8f,$30,$03,$a7,$fe,$de,$8d,$f9,
                                 $19,$c4,$1c,$91,$72,$3a,$01,$49,
                                 $ca,$a2,$08,$ae,$ce,$2d,$ec,$31,
                                 $91,$3b,$d8,$6e,$09,$a6,$98,$0f,
                                 $54,$59,$56,$f9,$a3,$c4,$b9,$65,
                                 $8a,$11,$74,$c6,$f6,$58,$a1,$ff,
                                 $cb,$23,$51,$01,$b7,$e8,$13,$8b,
                                 $f1,$92,$1f,$34,$42,$45,$9f,$4c,
                                 $57,$ab,$2d,$be,$8c,$cd,$03,$88,
                                 $d1,$44,$c4,$bb,$c0,$77,$62,$02,
                                 $af,$29,$7d,$ed,$5a,$10,$e7,$b3);
*)
var
  i: integer;
  k: longint;
  state: thashState;
  buf: array[0..1023] of byte;
const
  msgbits = 8*sizeof(msg);

begin
  {Win98, P4, 1.7GHz}

  {BP7:        1416.37s ->  0.72 MB/s}

  {D3:          248.76s ->  4.12 MB/s}
  {D6:          252.10s ->  4.06 MB/s}
  {D3/ASM32     191.03s ->  5.36 MB/s}
  {D3/Inlined   142.26s ->  7.20 MB/s}

  {D12:         140.61s ->  7.28 MB/s} {inline}
  {fpc224 -O3:  135.01s ->  7.58 MB/s} {inline}
  {fpc260 -O3:  148.41s ->  6.90 MB/s} {inline}

  {Win7-64, i3/2core, 2.3GHz}
  {fpc64:       65.317s -> 15.68 MB/s} {-O1 byte identical}
  {fpc64 -O3:   83.665s -> 12.24 MB/s} {!!, -O2 byte identical to -O3}

  writeln('Keccak-512 hashing 1 GB of data (ExtremelyLongMsgKAT_0.txt)');
  i := Init(state,512);
  for k:=1 to rep do begin
    if k and $FFFF = 0 then write('.');
    i := Update(state, @msg, msgbits);
    if i<>0 then begin
      writeln('Error ',i,' from update for k=',k);
      halt;
    end;
  end;
  i := Final(state,@buf);
  writeln;
  writeln(' Passed = ',compmem(@buf, @d512, sizeof(d512)));
end.

