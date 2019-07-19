{Simple test for chacha stream cipher, we 03.2010}

program T_CHACHA;

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}

uses
  {$ifdef WINCRT}
    WinCRT,
  {$endif}
  mem_util,
  salsa20;

{TVs from http://www.dsource.org/projects/tango/browser/trunk/tango/util/cipher/ChaCha.d?rev=5400}

const
  {WE: This is the first part of Set 1, vector#  0,  8 rounds/256 bits}
  key1: array[0..15] of byte = ($80,$00,$00,$00,$00,$00,$00,$00,
                                $00,$00,$00,$00,$00,$00,$00,$00);
   iv1: array[0..7]  of byte = ($00,$00,$00,$00,$00,$00,$00,$00);
   ct1: array[0..63] of byte = ($be,$b1,$e8,$1e,$0f,$74,$7e,$43,
                                $ee,$51,$92,$2b,$3e,$87,$fb,$38,
                                $d0,$16,$39,$07,$b4,$ed,$49,$33,
                                $60,$32,$ab,$78,$b6,$7c,$24,$57,
                                $9f,$e2,$8f,$75,$1b,$d3,$70,$3e,
                                $51,$d8,$76,$c0,$17,$fa,$a4,$35,
                                $89,$e6,$35,$93,$e0,$33,$55,$a7,
                                $d5,$7b,$23,$66,$f3,$00,$47,$c5);

const
  key2: array[0..15] of byte = ($00,$53,$a6,$f9,$4c,$9f,$f2,$45,
                                $98,$eb,$3e,$91,$e4,$37,$8a,$dd);
   iv2: array[0..7]  of byte = ($0d,$74,$db,$42,$a9,$10,$77,$de);
   ct2: array[0..63] of byte = ($50,$9b,$26,$7e,$72,$66,$35,$5f,
                                $a2,$dc,$0a,$25,$c0,$23,$fc,$e4,
                                $79,$22,$d0,$3d,$d9,$27,$54,$23,
                                $d7,$cb,$71,$18,$b2,$ae,$df,$22,
                                $05,$68,$85,$4b,$f4,$79,$20,$d6,
                                $fc,$0f,$d1,$05,$26,$cf,$e7,$f9,
                                $de,$47,$28,$35,$af,$c7,$3c,$91,
                                $6b,$84,$9e,$91,$ee,$e1,$f5,$29);

const
  {WE: This is the first part of Set 1, vector# 18,  8 rounds/256 bits}
  key3: array[0..31] of byte = ($00,$00,$20,$00,$00,$00,$00,$00,
                                $00,$00,$00,$00,$00,$00,$00,$00,
                                $00,$00,$00,$00,$00,$00,$00,$00,
                                $00,$00,$00,$00,$00,$00,$00,$00);
   iv3: array[0..7]  of byte = ($00,$00,$00,$00,$00,$00,$00,$00);
   ct3: array[0..63] of byte = ($65,$3f,$4a,$18,$e3,$d2,$7d,$af,
                                $51,$f8,$41,$a0,$0b,$6c,$1a,$2b,
                                $d2,$48,$98,$52,$d4,$ae,$07,$11,
                                $e1,$a4,$a3,$2a,$d1,$66,$fa,$6f,
                                $88,$1a,$28,$43,$23,$8c,$7e,$17,
                                $78,$6b,$a5,$16,$2b,$c0,$19,$d5,
                                $73,$84,$9c,$16,$76,$68,$51,$0a,
                                $da,$2f,$62,$b4,$ff,$31,$ad,$04);

const
  key4: array[0..31] of byte = ($0f,$62,$b5,$08,$5b,$ae,$01,$54,
                                $a7,$fa,$4d,$a0,$f3,$46,$99,$ec,
                                $3f,$92,$e5,$38,$8b,$de,$31,$84,
                                $d7,$2a,$7d,$d0,$23,$76,$c9,$1c);
   iv4: array[0..7]  of byte = ($28,$8f,$f6,$5d,$c4,$2b,$92,$f9);
   ct4: array[0..63] of byte = ($db,$16,$58,$14,$f6,$67,$33,$b7,
                                $a8,$e3,$4d,$1f,$fc,$12,$34,$27,
                                $12,$56,$d3,$bf,$8d,$8d,$a2,$16,
                                $69,$22,$e5,$98,$ac,$ac,$70,$f4,
                                $12,$b3,$fe,$35,$a9,$41,$90,$ad,
                                $0a,$e2,$e8,$ec,$62,$13,$48,$19,
                                $ab,$61,$ad,$dc,$cc,$fe,$99,$d8,
                                $67,$ca,$3d,$73,$18,$3f,$a3,$fd);

var
  buf,pt: array[0..63] of byte;
  ctx: salsa_ctx;

begin
  writeln('Simple test for Salsa20 stream cipher unit    (c) 2010 W.Ehrhardt');
  writeln(' Salsa20 stream cipher selftest: ', salsa_selftest);
  writeln('XSalsa20 stream cipher selftest: ', xsalsa_selftest);
  writeln('  ChaCha stream cipher selftest: ', chacha_selftest);
{$ifdef BIT32}
  writeln('  ChaChaBasm32 = ', ChaChaBasm32);
{$endif}

  fillchar(buf, sizeof(buf), 0);
  fillchar(pt , sizeof(pt),  0);
  chacha_xkeysetup(ctx, @key1, sizeof(key1)*8, 8);
  chacha_encrypt_packet(ctx, @IV1, @pt, @buf, 64);
  writeln('ChaCha test 1: ', compmem(@buf, @ct1, sizeof(ct1)));

  fillchar(buf, sizeof(buf), 0);
  fillchar(pt , sizeof(pt),  0);
  chacha_xkeysetup(ctx, @key2, sizeof(key2)*8, 8);
  chacha_encrypt_packet(ctx, @IV2, @pt, @buf, 64);
  writeln('ChaCha test 2: ', compmem(@buf, @ct2, sizeof(ct2)));

  fillchar(buf, sizeof(buf), 0);
  fillchar(pt , sizeof(pt),  0);
  chacha_xkeysetup(ctx, @key3, sizeof(key3)*8, 8);
  chacha_encrypt_packet(ctx, @IV3, @pt, @buf, 64);
  writeln('ChaCha test 3: ', compmem(@buf, @ct3, sizeof(ct3)));

  fillchar(buf, sizeof(buf), 0);
  fillchar(pt , sizeof(pt),  0);
  chacha_xkeysetup(ctx, @key4, sizeof(key4)*8, 8);
  chacha_encrypt_packet(ctx, @IV4, @pt, @buf, 64);
  writeln('ChaCha test 4: ', compmem(@buf, @ct4, sizeof(ct4)));

  fillchar(buf, sizeof(buf), 0);
  RandMem(@pt,sizeof(pt));
  chacha_keysetup(ctx, @key1);
  chacha_IVsetup(ctx, @IV1);
  chacha_encrypt_blocks(ctx, @pt, @buf, 1);
  chacha_keysetup(ctx, @key1);
  chacha_decrypt_packet(ctx, @IV1, @buf, @buf, 64);
  writeln('ChaCha test 5: ', compmem(@buf, @pt, sizeof(pt)));

  fillchar(buf, sizeof(buf), 0);
  RandMem(@pt,sizeof(pt));
  chacha_keysetup256(ctx, @key3);
  chacha_encrypt_packet(ctx, @IV3, @pt, @buf, 64);
  chacha_keysetup256(ctx, @key3);
  chacha_IVsetup(ctx, @IV3);
  chacha_decrypt_blocks(ctx, @buf, @buf, 1);
  writeln('ChaCha test 6: ', compmem(@buf, @pt, sizeof(pt)));

end.
