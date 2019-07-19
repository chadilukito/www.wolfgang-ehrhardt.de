{-Test prog for Keccak hash of 1 Million 'a'}

program t_speedk;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}


{$ifndef FPC}
  {$B-,N+}
{$endif}


uses
  {$ifdef WINCRT}
    wincrt,
  {$endif}
  mem_util,
  keccak_n;


type
  TKeccakMaxDigest = packed array[0..63] of byte;  {Keccak-512 digest}

var
  buf: array[1..1000] of byte;

var
  K224State: THashState;
  K256State: THashState;
  K384State: THashState;
  K512State: THashState;
  K224Dig:   TKeccakMaxDigest;
  K256Dig:   TKeccakMaxDigest;
  K384Dig:   TKeccakMaxDigest;
  K512Dig:   TKeccakMaxDigest;

{Test vectors from http://www.di-mgt.com.au/sha_testvectors.html}

const
  C224: array[0..27] of byte = ($19,$f9,$16,$7b,$e2,$a0,$4c,$43,
                                $ab,$d0,$ed,$55,$47,$88,$10,$1b,
                                $9c,$33,$90,$31,$ac,$c8,$e1,$46,
                                $85,$31,$30,$3f);


  C256: array[0..31] of byte = ($fa,$da,$e6,$b4,$9f,$12,$9b,$bb,
                                $81,$2b,$e8,$40,$7b,$7b,$28,$94,
                                $f3,$4a,$ec,$f6,$db,$d1,$f9,$b0,
                                $f0,$c7,$e9,$85,$30,$98,$fc,$96);


  C384: array[0..47] of byte = ($0c,$83,$24,$e1,$eb,$c1,$82,$82,
                                $2c,$5e,$2a,$08,$6c,$ac,$07,$c2,
                                $fe,$00,$e3,$bc,$e6,$1d,$01,$ba,
                                $8a,$d6,$b7,$17,$80,$e2,$de,$c5,
                                $fb,$89,$e5,$ae,$90,$cb,$59,$3e,
                                $57,$bc,$62,$58,$fd,$d9,$4e,$17);


  C512: array[0..63] of byte = ($5c,$f5,$3f,$2e,$55,$6b,$e5,$a6,
                                $24,$42,$5e,$de,$23,$d0,$e8,$b2,
                                $c7,$81,$4b,$4b,$a0,$e4,$e0,$9c,
                                $bb,$f3,$c2,$fa,$c7,$05,$6f,$61,
                                $e0,$48,$fc,$34,$12,$62,$87,$5e,
                                $bc,$58,$a5,$18,$3f,$ea,$65,$14,
                                $47,$12,$43,$70,$c1,$eb,$f4,$d6,
                                $c8,$9b,$c9,$a7,$73,$10,$63,$bb);

var
  i,err: integer;
begin

  writeln('Test 10^6 repetitions of "a"');
  writeln('----------------------------');
  fillchar(buf, sizeof(buf), $61 {='a'});
  err := 0;

  {Init contexts}
  err := err or Init(K224State, 224);
  err := err or Init(K256State, 256);
  err := err or Init(K384State, 384);
  err := err or Init(K512State, 512);
  if err<>0 then begin
    writeln('Error during Init');
    halt;
  end;

  {absorb 1000*1000 'a'}
  err := 0;
  for i:=1 to 1000 do begin
    {$ifdef debug}
      if i mod 100 = 0 then write(i,#13);
    {$endif}
    err := err or Update(K224State, @buf, 8000);
    err := err or Update(K256State, @buf, 8000);
    err := err or Update(K384State, @buf, 8000);
    err := err or Update(K512State, @buf, 8000);
  end;

  if err<>0 then writeln('Error during Update');

  err := 0;
  err := err or Final(K224State, @K224Dig);
  err := err or Final(K256State, @K256Dig);
  err := err or Final(K384State, @K384Dig);
  err := err or Final(K512State, @K512Dig);
  if err<>0 then writeln('Error during Final');

  {write test results}
  writeln(' Keccak-224: ',  compmem(@K224Dig, @C224, sizeof(C224)));
  writeln(' Keccak-256: ',  compmem(@K256Dig, @C256, sizeof(C256)));
  writeln(' Keccak-384: ',  compmem(@K384Dig, @C384, sizeof(C384)));
  writeln(' Keccak-512: ',  compmem(@K512Dig, @C512, sizeof(C512)));

end.

