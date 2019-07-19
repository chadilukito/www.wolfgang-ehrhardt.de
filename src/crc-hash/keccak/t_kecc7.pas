program t_kecc7;

{Monte Carlo known answer test for Keccak f[1600],  WE  Nov.2012}
{Test vectors from MonteCarlo_xx.txt, j=99, xx=0,224,256,384,512}

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}


uses
  {$ifdef WINCRT} WinCRT, {$endif}
  BTypes, Mem_Util, keccak_n;


const
  seed: array[0..127] of byte = ($6c,$d4,$c0,$c5,$cb,$2c,$a2,$a0,
                                 $f1,$d1,$ae,$ce,$ba,$c0,$3b,$52,
                                 $e6,$4e,$a0,$3d,$1a,$16,$54,$37,
                                 $29,$36,$54,$5b,$92,$bb,$c5,$48,
                                 $4a,$59,$db,$74,$bb,$60,$f9,$c4,
                                 $0c,$eb,$1a,$5a,$a3,$5a,$6f,$af,
                                 $e8,$03,$49,$e1,$4c,$25,$3a,$4e,
                                 $8b,$1d,$77,$61,$2d,$dd,$81,$ac,
                                 $e9,$26,$ae,$8b,$0a,$f6,$e5,$31,
                                 $76,$db,$ff,$cc,$2a,$6b,$88,$c6,
                                 $bd,$76,$5f,$93,$9d,$3d,$17,$8a,
                                 $9b,$de,$9e,$f3,$aa,$13,$1c,$61,
                                 $e3,$1c,$1e,$42,$cd,$fa,$f4,$b4,
                                 $dc,$de,$57,$9a,$37,$e1,$50,$ef,
                                 $be,$f5,$55,$5b,$4c,$1c,$b4,$04,
                                 $39,$d8,$35,$a7,$24,$e2,$fa,$e7);

  t224: array[0.. 27] of byte = ($11,$d9,$78,$de,$9f,$5c,$13,$4b,
                                 $43,$4e,$98,$e6,$31,$27,$20,$66,
                                 $e8,$6b,$b0,$f5,$b0,$77,$11,$f2,
                                 $a4,$1e,$f0,$89);

  t256: array[0.. 31] of byte = ($5e,$c1,$4b,$3d,$56,$83,$3e,$a0,
                                 $70,$f4,$df,$d6,$b0,$c3,$19,$f5,
                                 $d2,$f4,$cb,$77,$5f,$84,$8b,$8c,
                                 $2d,$59,$8e,$07,$c0,$63,$a1,$5a);


  t384: array[0.. 47] of byte = ($df,$da,$2f,$f7,$83,$b6,$ff,$79,
                                 $7d,$96,$f2,$7a,$78,$c0,$25,$bb,
                                 $5f,$7e,$9a,$24,$c3,$06,$17,$1d,
                                 $80,$91,$aa,$a0,$b7,$97,$87,$be,
                                 $ec,$1d,$48,$89,$72,$f7,$0b,$58,
                                 $c7,$4f,$f0,$8d,$5b,$ca,$91,$1e);


  t512: array[0.. 63] of byte = ($d1,$f5,$17,$57,$7f,$4b,$50,$33,
                                 $44,$93,$5c,$b7,$25,$a6,$ef,$fa,
                                 $f5,$23,$a5,$43,$ea,$fe,$ee,$12,
                                 $7f,$cb,$85,$2d,$6b,$ef,$33,$e0,
                                 $48,$76,$af,$d5,$50,$49,$99,$ed,
                                 $63,$ca,$7f,$02,$6f,$60,$f1,$a3,
                                 $0d,$f2,$ed,$a3,$6c,$5c,$62,$82,
                                 $95,$7e,$15,$0f,$03,$e6,$06,$71);


  t000: array[0.. 63] of byte = ($59,$41,$5a,$96,$e0,$2f,$cd,$16,
                                 $95,$24,$7d,$3b,$4b,$39,$0f,$f6,
                                 $83,$3b,$a9,$3a,$b4,$ee,$4e,$da,
                                 $c6,$aa,$52,$5c,$12,$70,$8c,$52,
                                 $14,$45,$1c,$58,$b4,$79,$d6,$64,
                                 $d1,$e2,$2e,$01,$c3,$96,$27,$3e,
                                 $17,$42,$66,$b3,$ac,$96,$83,$79,
                                 $ea,$dc,$e9,$df,$24,$c7,$a3,$41);


{---------------------------------------------------------------------------}
procedure mct_0;
  {-MCT with iterative squeezing of 64 bytes}
var
  state: thashState;
  md: array[0..127] of byte;
  i,j,err: integer;
begin
  write('  Squeeze 512 bits: ');
  err := Init(state,0);
  if err<>0 then begin
    writeln(' Init error ',err);
    exit;
  end;
  err := Update(state, @seed, sizeof(seed)*8);
  if err<>0 then begin
    writeln(' Update error ',err);
    exit;
  end;
  Err := Final(state, @md);
  if err<>0 then begin
    writeln(' Final error ',err);
    exit;
  end;
  for j:=0 to 99 do begin
    if odd(j) then write('.');
    for i:=1 to 1000 do begin
      err := Squeeze(state, @md, 512);
      if err<>0 then begin
        writeln(' Squeeze error ',err);
        exit;
      end;
    end;
  end;
  writeln(compmem(@md, @t000, sizeof(t000)):6);
end;


{---------------------------------------------------------------------------}
procedure monte_carlo(HashBitlen: integer; digp: pointer; digbytes: integer);
var
  msg,md: array[0..127] of byte;
  i,j,k,err,bl: integer;
begin
  if HashBitlen=0 then mct_0
  else begin
    write('  Keccak  ',HashBitlen,' bits: ');
    move(seed, msg, sizeof(msg));
    bl := HashBitlen div 8;
    for j:=0 to 99 do begin
      if odd(j) then write('.');
      for i:=1 to 1000 do begin
        err := KeccakFullBytes(HashBitlen, @msg, sizeof(msg), @md);
        if err<>0 then begin
          writeln(' KeccakFull error ',err);
          exit;
        end;
        for k:=127 downto bl do msg[k] := msg[k-bl];
        for k:=0 to bl-1 do msg[k] := md[k];
      end;
    end;
    writeln(compmem(@md, digp, digbytes):6);
  end;
end;

begin
  writeln('Keccak SHA-3 Monte Carlo Known Answer Test');
  monte_carlo(224, @t224, sizeof(t224));
  monte_carlo(256, @t256, sizeof(t256));
  monte_carlo(384, @t384, sizeof(t384));
  monte_carlo(512, @t512, sizeof(t512));
  monte_carlo(  0, @t000, sizeof(t000));
end.

