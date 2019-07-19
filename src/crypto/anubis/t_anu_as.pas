{-Prog for associativity of CFB,OFB,CTR modes, (c) we Aug.2008}

program T_ANU_AS;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  anu_base,anu_ctr,anu_cfb,anu_ofb,BTypes,mem_util;

const
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);

      IV : TANUBlock =            ($00,$01,$02,$03,$04,$05,$06,$07,
                                   $08,$09,$0a,$0b,$0c,$0d,$0e,$0f);

     CTR : TANUBlock =            ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7,
                                   $f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

  plain  : array[0..63] of byte = ($6b,$c1,$be,$e2,$2e,$40,$9f,$96,
                                   $e9,$3d,$7e,$11,$73,$93,$17,$2a,
                                   $ae,$2d,$8a,$57,$1e,$03,$ac,$9c,
                                   $9e,$b7,$6f,$ac,$45,$af,$8e,$51,
                                   $30,$c8,$1c,$46,$a3,$5c,$e4,$11,
                                   $e5,$fb,$c1,$19,$1a,$0a,$52,$ef,
                                   $f6,$9f,$24,$45,$df,$4f,$9b,$17,
                                   $ad,$2b,$41,$7b,$e6,$6c,$37,$10);

  ct_cfb : array[0..63] of byte = ($02,$4f,$81,$75,$30,$56,$dc,$a4,
                                   $49,$10,$9d,$9e,$38,$43,$f2,$4e,
                                   $74,$54,$c2,$c5,$24,$d1,$c6,$29,
                                   $35,$54,$1d,$d2,$7a,$58,$4c,$61,
                                   $12,$6c,$e5,$51,$97,$89,$12,$07,
                                   $0f,$f6,$cf,$14,$f8,$e7,$fe,$68,
                                   $4d,$f2,$ce,$8f,$1d,$fc,$7c,$d2,
                                   $37,$31,$e6,$07,$cf,$ce,$f5,$bd);

  ct_ctr : array[0..63] of byte = ($44,$b9,$7c,$f7,$24,$50,$e7,$27,
                                   $62,$7d,$d5,$06,$9f,$78,$86,$b0,
                                   $34,$87,$6c,$c6,$25,$ab,$4b,$2a,
                                   $17,$cb,$d2,$6d,$8f,$42,$06,$c2,
                                   $18,$e3,$92,$7b,$95,$29,$55,$3b,
                                   $a9,$94,$8a,$a0,$27,$a2,$bb,$5f,
                                   $1f,$34,$1f,$77,$bf,$14,$26,$10,
                                   $7c,$e5,$47,$49,$81,$84,$75,$29);

  ct_ofb : array[0..63] of byte = ($02,$4f,$81,$75,$30,$56,$dc,$a4,
                                   $49,$10,$9d,$9e,$38,$43,$f2,$4e,
                                   $02,$93,$7b,$0c,$f3,$dc,$fc,$e3,
                                   $62,$1c,$33,$92,$20,$57,$d7,$71,
                                   $5e,$d5,$05,$00,$73,$f8,$a8,$36,
                                   $35,$fe,$66,$e3,$61,$42,$25,$81,
                                   $68,$f1,$d7,$a8,$51,$f2,$8c,$dc,
                                   $6c,$e6,$4a,$17,$da,$b4,$4c,$f7);

var
  ct: array[0..63] of byte;

var
  Context: TANUContext;


{---------------------------------------------------------------------------}
function test(px,py: pointer): str255;
begin
  if compmem(px,py,64) then test := 'OK' else test := 'Error';
end;


{---------------------------------------------------------------------------}
procedure TestCFB;
var
  i: integer;
  pp,pc: pointer;
begin
  if ANU_CFB_Init(key128, 128, IV, context)<>0 then begin
    writeln('*** Error CFB');
    exit;
  end;
  pp := @plain;
  pc := @ct;
  for i:=1 to sizeof(plain) do begin
    if ANU_CFB_Encrypt(pp, pc, 1, context)<>0 then begin
      writeln('*** Error CFB');
      exit;
    end;
    inc(Ptr2Inc(pp));
    inc(Ptr2Inc(pc));
  end;
  writeln('CFB  test: ', test(@ct,@ct_cfb));
end;


{---------------------------------------------------------------------------}
procedure TestCTR;
var
  i: integer;
  pp,pc: pointer;
begin
  if ANU_CTR_Init(key128, 128, CTR, context)<>0 then begin
    writeln('*** Error CTR');
    exit;
  end;
  pp := @plain;
  pc := @ct;
  for i:=1 to sizeof(plain) do begin
    if ANU_CTR_Encrypt(pp, pc, 1, context)<>0 then begin
      writeln('*** Error CTR');
      exit;
    end;
    inc(Ptr2Inc(pp));
    inc(Ptr2Inc(pc));
  end;
  writeln('CTR  test: ', test(@ct,@ct_ctr));
end;


{---------------------------------------------------------------------------}
procedure TestOFB;
var
  i: integer;
  pp,pc: pointer;
begin
  if ANU_OFB_Init(key128, 128, IV, context)<>0 then begin
    writeln('*** Error OFB');
    exit;
  end;
  pp := @plain;
  pc := @ct;
  for i:=1 to sizeof(plain) do begin
    if ANU_OFB_Encrypt(pp, pc, 1, context)<>0 then begin
      writeln('*** Error OFB');
      exit;
    end;
    inc(Ptr2Inc(pp));
    inc(Ptr2Inc(pc));
  end;
  writeln('OFB  test: ', test(@ct,@ct_ofb));
end;


begin
  writeln('Test program "Associativity of CFB,OFB,CTR"    (C) 2008  W.Ehrhardt');
  ANU_SetFastInit(true);
  TestCFB;
  TestCTR;
  TestOFB;
end.
