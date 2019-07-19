{Speed test program for StreamSec Blowfish Unit , W.Ehrhardt Dec 2004}
{compile in OpenStrSecII\Source directory}

{http://sourceforge.net/projects/openstrsecii/, V2.1.8.221}
{Copyright (c) 2004, Henrick Wibell Hellstr”m, StreamSec}


program t_bf_ss;


{$apptype console}

{$J+}

uses
  SysUtils, Classes,
  SsBlowfish;

var
  BFish: TBlowfish_ECB;

var
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);

      IV : array[0..07] of byte = ($00,$01,$02,$03,$04,$05,$06,$07);

     CTR : array[0..07] of byte = ($f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

     {OpenStrSecII needs string IVs/CTRs, array of char unusable with #0}
     IVS : string[8] = #$00#$01#$02#$03#$04#$05#$06#$07;

     {OpenStrSecII increments counter before first use!!}
     CTRS: string[8] = #$f8#$f9#$fa#$fb#$fc#$fd#$fe#$fe;

  plain  : array[0..63] of char = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  ct_cbc : array[0..63] of byte = ($85,$5c,$44,$94,$53,$b4,$c1,$c3,
                                   $2e,$9d,$1a,$75,$bc,$dc,$86,$d3,
                                   $7e,$ea,$41,$da,$e9,$c1,$96,$bd,
                                   $8e,$e6,$f2,$0c,$18,$56,$e1,$60,
                                   $86,$bb,$28,$0d,$c1,$31,$39,$1c,
                                   $2f,$34,$ae,$ed,$02,$a9,$d7,$32,
                                   $4e,$63,$03,$91,$af,$14,$51,$0e,
                                   $26,$11,$bc,$f8,$33,$83,$fa,$4e);


  ct_cfb : array[0..63] of byte = ($1d,$9c,$d3,$8f,$2a,$12,$e1,$16,
                                   $28,$30,$e0,$71,$9d,$7a,$2e,$f3,
                                   $0b,$de,$7a,$07,$27,$7a,$c4,$49,
                                   $4d,$85,$4e,$06,$be,$a5,$4b,$aa,
                                   $a3,$84,$d5,$07,$1f,$23,$9c,$55,
                                   $a3,$e4,$d5,$87,$87,$b5,$d2,$fd,
                                   $57,$d8,$4d,$d9,$ad,$2c,$c5,$d1,
                                   $f1,$7e,$37,$b1,$3e,$c4,$26,$84);

  ct_ctr : array[0..63] of byte = ($81,$07,$98,$2d,$92,$73,$12,$40,
                                   $ba,$58,$c1,$c9,$32,$f7,$ea,$67,
                                   $f3,$a9,$8f,$eb,$25,$51,$fa,$c2,
                                   $5c,$17,$80,$be,$6b,$a0,$39,$e5,
                                   $dc,$1f,$eb,$c3,$81,$53,$af,$20,
                                   $bd,$15,$6d,$4b,$89,$65,$8a,$d5,
                                   $6c,$a1,$dc,$0e,$a0,$07,$5b,$c3,
                                   $8e,$3c,$b4,$6d,$9e,$af,$a1,$64);

  ct_ofb : array[0..63] of byte = ($1d,$9c,$d3,$8f,$2a,$12,$e1,$16,
                                   $07,$7c,$db,$a3,$73,$5a,$b2,$a4,
                                   $f9,$de,$06,$8b,$03,$e0,$a7,$ed,
                                   $33,$f1,$6f,$79,$ec,$76,$55,$75,
                                   $07,$6d,$24,$ae,$aa,$2d,$60,$ab,
                                   $2d,$ce,$34,$9f,$b2,$d6,$eb,$b5,
                                   $40,$83,$56,$a4,$fd,$38,$8c,$e6,
                                   $2c,$11,$16,$88,$4c,$67,$07,$76);

  ct_ecb : array[0..63] of byte = ($14,$e7,$78,$36,$6e,$88,$69,$95,
                                   $65,$5a,$28,$bd,$a8,$84,$98,$3e,
                                   $54,$48,$78,$c4,$d8,$61,$ae,$2b,
                                   $98,$ad,$ec,$ec,$b4,$5f,$1c,$b5,
                                   $6d,$be,$e7,$f1,$5f,$26,$50,$2f,
                                   $96,$19,$f6,$c3,$a6,$59,$d7,$f9,
                                   $74,$5c,$07,$81,$2a,$0d,$21,$7f,
                                   $9e,$98,$cb,$ec,$ce,$3e,$8a,$71);


var
  ct: array[0..63] of byte;

const
  N : longint = 8*1000000;


{---------------------------------------------------------------------------}
function CompMem(psrc, pdest: pointer; size: word): boolean;
  {-compare memory block}
var
  i: word;
begin
  CompMem := false;
  for i:=1 to size do begin
    if pByte(psrc)^<>pByte(pdest)^ then exit;
    inc(longint(psrc));
    inc(longint(pdest));
  end;
  CompMem := true;
end;


{---------------------------------------------------------------------------}
function test(px,py: pointer): string;
begin
  if compmem(px,py,64) then test := 'OK' else test := 'Error';
end;


procedure TestECB;
var
  i: integer;
begin
   BFish := TBlowfish_ECB.Create(Key128,sizeof(Key128),0);
   for i:=1 to N do begin
     move(plain,ct,sizeof(plain));
     BFish.Encrypt(ct,sizeof(ct));
   end;
   if N=1 then begin
     writeln('ECB test: ', test(@ct,@ct_ecb));
   end;
   BFish.Free;
end;


procedure TestCFB;
var
  i: integer;
begin
   BFish := TBlowfish_CFB.Create(Key128,sizeof(Key128),0);
   BFish.IVector := IVs;
   for i:=1 to N do begin
     move(plain,ct,sizeof(plain));
     BFish.Encrypt(ct,sizeof(ct));
   end;
   if N=1 then begin
     writeln('CFB test: ', test(@ct,@ct_cfb));
   end;                                       
   BFish.Free;
end;

procedure TestCTR;
var
  i: integer;
begin
   BFish := TBlowfish_CTR.Create(Key128,sizeof(Key128),0);
   BFish.IVector := CTRs;
   for i:=1 to N do begin
     move(plain,ct,sizeof(plain));
     BFish.Encrypt(ct,sizeof(ct));
   end;
   if N=1 then begin
     writeln('CTR test: ', test(@ct,@ct_ctr));
   end;
   BFish.Free;
end;

procedure TestOFB;
var
  i: integer;
begin
   BFish := TBlowfish_OFB.Create(Key128,sizeof(Key128),0);
   BFish.IVector := IVs;
   for i:=1 to N do begin
     move(plain,ct,sizeof(plain));
     BFish.Encrypt(ct,sizeof(ct));
   end;
   if N=1 then begin
     writeln('OFB test: ', test(@ct,@ct_ofb));
   end;
   BFish.Free;
end;

procedure TestCBC;
var
  i: integer;
begin
   BFish := TBlowfish_CBC.Create(Key128,sizeof(Key128),0);
   BFish.IVector := IVs;
   for i:=1 to N do begin
     move(plain,ct,sizeof(plain));
     BFish.Encrypt(ct,sizeof(ct));
   end;
   if N=1 then begin
     writeln('CBC test: ', test(@ct,@ct_cbc));
   end;
   BFish.Free;
end;

var
  s: string;
begin
  s := Uppercase(paramstr(1));
  if s='TEST' then begin
    N := 1;
    TestECB;
    TestCBC;
    TestCFB;
    TestCTR;
    TestOFB;
  end
  else if s='ECB' then TestECB
  else if s='CBC' then TestCBC
  else if s='CFB' then TestCFB
  else if s='CTR' then TestCTR
  else if s='OFB' then TestOFB
  else writeln('Usage: ', ExtractFilename(paramstr(0)), '  [ TEST | CBC | CFB | CTR | ECB| OFB ]');
  if DebugHooK>0 then begin
    write('Enter'); readln;
  end;
end.
