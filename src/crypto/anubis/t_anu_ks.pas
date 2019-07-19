{-Test program for basic Anubis functions, (c) we Aug.2008}
program t_an_ks;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  mem_util,anu_base;


{Data from Set 3, vector# 42 of anubis-test-vectors-xxx.txt, xxx=128..320}

const
    key: array[0..39] of byte = (
            $2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,
            $2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,
            $2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,
            $2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,
            $2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a);

  plain: TANUBlock = ($2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a,$2a);

    ct1: array[4..10] of TANUBlock = (
           ($35,$7d,$9d,$07,$f9,$9c,$d3,$23,$21,$a8,$ca,$d6,$cc,$25,$d8,$04),
           ($2f,$2b,$67,$c0,$e4,$60,$6c,$82,$73,$19,$d4,$2b,$17,$44,$a2,$07),
           ($89,$fc,$95,$ca,$eb,$dd,$4b,$17,$37,$68,$f8,$87,$94,$a7,$b5,$cf),
           ($f3,$1a,$9f,$ef,$26,$b2,$d1,$fa,$3e,$eb,$c0,$c0,$71,$64,$3d,$e4),
           ($eb,$e0,$0c,$32,$7a,$1d,$7f,$d7,$01,$c4,$5f,$cd,$72,$87,$22,$93),
           ($b1,$f9,$af,$68,$5a,$8f,$13,$96,$8a,$98,$5c,$96,$50,$91,$74,$2d),
           ($0c,$17,$76,$2a,$6f,$2c,$75,$6c,$2c,$64,$5a,$c8,$ff,$27,$52,$04));

  ct100: array[4..10] of TANUBlock = (
           ($5a,$4d,$75,$5a,$f4,$97,$bc,$99,$b9,$b6,$26,$a4,$96,$50,$60,$32),
           ($e0,$6c,$93,$70,$84,$6f,$7d,$25,$4f,$39,$21,$fe,$69,$f4,$73,$ac),
           ($7c,$58,$60,$ea,$96,$29,$40,$08,$66,$e1,$42,$89,$1c,$61,$9f,$ea),
           ($ef,$6f,$2e,$20,$5f,$5d,$af,$4d,$4e,$b2,$57,$ca,$bf,$b4,$bb,$26),
           ($c8,$f7,$21,$90,$5b,$ee,$1e,$ef,$7d,$cc,$eb,$2b,$f4,$9e,$d0,$87),
           ($14,$fb,$98,$18,$bd,$f7,$88,$fe,$2f,$46,$04,$85,$87,$f6,$5d,$a4),
           ($06,$d8,$ef,$38,$57,$58,$9c,$d2,$96,$c6,$d1,$76,$a9,$4e,$a6,$35));

 ct1000: array[4..10] of TANUBlock = (
           ($4c,$3f,$78,$2e,$7a,$31,$18,$dd,$34,$a0,$da,$64,$3f,$2b,$29,$8a),
           ($03,$83,$30,$5b,$12,$c4,$84,$23,$69,$8d,$48,$31,$0c,$eb,$4f,$49),
           ($6f,$f1,$d0,$e4,$aa,$f6,$0c,$b8,$b5,$9a,$62,$f5,$a3,$13,$0d,$46),
           ($25,$58,$72,$4b,$c8,$70,$af,$ea,$d7,$f0,$6f,$53,$77,$59,$0d,$7f),
           ($c0,$73,$7c,$0d,$27,$46,$31,$9d,$4b,$e1,$e8,$b6,$b6,$c5,$19,$b5),
           ($42,$cf,$8c,$5e,$66,$59,$5f,$b9,$47,$7c,$31,$45,$29,$ba,$1c,$83),
           ($4f,$86,$53,$82,$86,$1f,$a7,$f6,$9f,$9a,$43,$92,$4b,$bf,$a4,$cd));
var
  ctx: TANUContext;
  i,err,n,ec: integer;
  t1,t100,t1000: TANUBlock;
label
  next;
begin
  writeln('Check test vectors for Anubis key sizes 128..320 bit  (C) 2008  W.Ehrhardt');
  for n:=4 to 10 do begin
    ec := 0;
    write('Key size ',32*n, ' bits ... ');
    err := ANU_Init_Encr(Key, 32*n, ctx);
    if err<>0 then begin
      writeln('Error ANU_Init_Encr: ',err);
      inc(ec);
      goto next;
    end;
    ANU_Encrypt(ctx, plain, t1);
    if not compmem(@t1, @ct1[n], sizeof(TANUBlock)) then begin
      writeln('Error ct1');
      inc(ec);
    end;
    t100 := plain;
    for i:=1 to 100 do ANU_Encrypt(ctx, t100, t100);
    if not compmem(@t100, @ct100[n], sizeof(TANUBlock)) then begin
      writeln('Error ct100');
      inc(ec);
    end;
    t1000 := plain;
    for i:=1 to 1000 do ANU_Encrypt(ctx, t1000, t1000);
    if not compmem(@t1000, @ct1000[n], sizeof(TANUBlock)) then begin
      writeln('Error ct100');
      inc(ec);
    end;

    err := ANU_Init_Decr(Key, 32*n, ctx);
    if err<>0 then begin
      writeln('Error ANU_Init_Dncr: ',err);
      inc(ec);
      goto next;
    end;

    ANU_Decrypt(ctx, t1, t1);
    if not compmem(@t1, @plain, sizeof(TANUBlock)) then begin
      writeln('Error decr1');
      inc(ec);
    end;
    for i:=1 to 100 do ANU_Decrypt(ctx, t100, t100);
    if not compmem(@t100, @plain, sizeof(TANUBlock)) then begin
      writeln('Error decr100');
      inc(ec);
    end;
    for i:=1 to 1000 do ANU_Decrypt(ctx, t1000, t1000);
    if not compmem(@t1000, @plain, sizeof(TANUBlock)) then begin
      writeln('Error decr1000');
      inc(ec);
    end;
next:
    if ec=0 then writeln('OK');
  end;
end.
