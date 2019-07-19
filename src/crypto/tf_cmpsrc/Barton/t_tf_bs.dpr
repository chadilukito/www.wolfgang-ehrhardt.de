{Twofish speed test program for Barton dcpcrypt2 , W.Ehrhardt May 2006}
{compile with c_tf_bs.bat in dcpcrypt2 base direytory}

program t_tf_bs;


{$apptype console}

{$J+}

uses
  SysUtils, Classes,
  DCPcrypt2, DCPblockciphers, DCPTwoFish;

var
  MyTF: TDCP_twofish;

var
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);

      IV : array[0..15] of byte = ($00,$01,$02,$03,$04,$05,$06,$07,
                                   $08,$09,$0a,$0b,$0c,$0d,$0e,$0f);

     CTR : array[0..15] of byte = ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7,
                                   $f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

  plain  : array[0..63] of byte = ($6b,$c1,$be,$e2,$2e,$40,$9f,$96,
                                   $e9,$3d,$7e,$11,$73,$93,$17,$2a,
                                   $ae,$2d,$8a,$57,$1e,$03,$ac,$9c,
                                   $9e,$b7,$6f,$ac,$45,$af,$8e,$51,
                                   $30,$c8,$1c,$46,$a3,$5c,$e4,$11,
                                   $e5,$fb,$c1,$19,$1a,$0a,$52,$ef,
                                   $f6,$9f,$24,$45,$df,$4f,$9b,$17,
                                   $ad,$2b,$41,$7b,$e6,$6c,$37,$10);

  ct_cbc : array[0..63] of byte = ($C2,$06,$7A,$C0,$F3,$66,$92,$C1,
                                   $5E,$0F,$BB,$EF,$48,$AC,$F4,$AB,
                                   $9A,$C6,$7B,$E6,$45,$E8,$A1,$62,
                                   $6F,$B2,$AC,$79,$85,$82,$52,$4E,
                                   $83,$E6,$98,$C4,$76,$34,$39,$F9,
                                   $A2,$CD,$A9,$83,$61,$30,$11,$58,
                                   $0A,$01,$DA,$9B,$CE,$A1,$24,$4C,
                                   $09,$91,$71,$4E,$ED,$75,$F5,$CD);


  ct_cfb : array[0..63] of byte = ($99,$27,$9B,$8C,$6C,$EA,$EC,$58,
                                   $2D,$EA,$F8,$BC,$7A,$A3,$80,$EE,
                                   $00,$D2,$27,$42,$4E,$59,$3B,$61,
                                   $29,$0A,$3D,$57,$77,$A2,$32,$81,
                                   $E2,$EC,$DC,$8B,$F2,$BB,$AF,$6D,
                                   $17,$61,$C4,$E1,$FC,$A3,$E7,$1A,
                                   $7C,$F5,$A0,$B2,$98,$E1,$FD,$2F,
                                   $0E,$A0,$7C,$96,$7E,$A0,$F8,$8B);

  ct_ctr : array[0..63] of byte = ($58,$3C,$41,$1E,$DD,$52,$A0,$93,
                                   $08,$8B,$83,$8D,$27,$90,$CA,$6B,
                                   $AF,$9C,$CB,$65,$4A,$BF,$72,$D2,
                                   $DE,$D8,$39,$D6,$58,$EB,$3E,$9F,
                                   $4F,$98,$6B,$4A,$E8,$56,$87,$86,
                                   $36,$17,$F1,$AA,$59,$9A,$BB,$6F,
                                   $F5,$DA,$8E,$DF,$75,$61,$41,$8D,
                                   $9B,$66,$EF,$C0,$32,$8D,$DC,$CA);

  ct_ofb : array[0..63] of byte = ($99,$27,$9B,$8C,$6C,$EA,$EC,$58,
                                   $2D,$EA,$F8,$BC,$7A,$A3,$80,$EE,
                                   $A8,$C3,$68,$CF,$8D,$2F,$58,$FE,
                                   $35,$B7,$71,$B0,$99,$40,$14,$56,
                                   $28,$17,$71,$AC,$BA,$01,$C9,$A6,
                                   $FF,$50,$80,$AD,$9D,$02,$42,$77,
                                   $C2,$09,$8D,$19,$66,$AB,$7C,$1E,
                                   $52,$A1,$FD,$FF,$2D,$05,$5D,$CA);


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
var
  i: integer;
begin
  if compmem(px,py,64) then test := 'OK' else test := 'Error';
end;


procedure TestCFB;
var
  i: integer;
begin
   MyTF.CipherMode := cmCFBBlock;
   MyTF.Init(key128,128,@IV);
   for i:=1 to N do MyTF.EncryptCFBblock(plain,ct,sizeof(plain));
   if N=1 then begin
     writeln('CFB test: ', test(@ct,@ct_cfb));
   end;
end;

procedure TestCTR;
var
  i: integer;
begin
   MyTF.CipherMode := cmCTR;
   MyTF.Init(key128,128,@CTR);
   for i:=1 to N do MyTF.EncryptCTR(plain,ct,sizeof(plain));
   if N=1 then begin
     writeln('CTR test: ', test(@ct,@ct_ctr));
   end;
end;

procedure TestOFB;
var
  i: integer;
begin
   MyTF.CipherMode := cmOFB;
   MyTF.Init(key128,128,@IV);
   for i:=1 to N do MyTF.EncryptOFB(plain,ct,sizeof(plain));
   if N=1 then begin
     writeln('OFB test: ', test(@ct,@ct_ofb));
   end;
end;

procedure TestCBC;
var
  i: integer;
begin
   MyTF.CipherMode := cmCBC;
   MyTF.Init(key128,128,@IV);
   for i:=1 to N do MyTF.EncryptCBC(plain,ct,sizeof(plain));
   if N=1 then begin
     writeln('CBC test: ', test(@ct,@ct_cbc));
   end;
end;

var
  s: string;
begin
  MyTF := TDCP_twofish.Create(nil);
  s := Uppercase(paramstr(1));
  if s='TEST' then begin
    N := 1;
    TestCBC;
    TestCFB;
    TestCTR;
    TestOFB;
  end
  else if s='CBC' then TestCBC
  else if s='CFB' then TestCFB
  else if s='CTR' then TestCTR
  else if s='OFB' then TestOFB
  else writeln('Usage: ', ExtractFilename(paramstr(0)), '  [ TEST | CBC | CFB | CTR | OFB ]');
  if DebugHooK>0 then begin
    write('Enter'); readln;
  end;
end.
