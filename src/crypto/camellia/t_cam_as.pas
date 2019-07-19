{-Prog for associativity of CFB,OFB,CTR modes, (c) we Sep.2008}

program T_CAM_AS;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  BTypes,cam_base,cam_ctr,cam_cfb,cam_ofb,mem_util;

const
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);

      IV : TCAMBlock =            ($00,$01,$02,$03,$04,$05,$06,$07,
                                   $08,$09,$0a,$0b,$0c,$0d,$0e,$0f);

     CTR : TCAMBlock =            ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7,
                                   $f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

  plain  : array[0..63] of byte = ($6b,$c1,$be,$e2,$2e,$40,$9f,$96,
                                   $e9,$3d,$7e,$11,$73,$93,$17,$2a,
                                   $ae,$2d,$8a,$57,$1e,$03,$ac,$9c,
                                   $9e,$b7,$6f,$ac,$45,$af,$8e,$51,
                                   $30,$c8,$1c,$46,$a3,$5c,$e4,$11,
                                   $e5,$fb,$c1,$19,$1a,$0a,$52,$ef,
                                   $f6,$9f,$24,$45,$df,$4f,$9b,$17,
                                   $ad,$2b,$41,$7b,$e6,$6c,$37,$10);

  ct_cfb : array[0..63] of byte = ($14,$f7,$64,$61,$87,$81,$7e,$b5,
                                   $86,$59,$91,$46,$b8,$2b,$d7,$19,
                                   $a5,$3d,$28,$bb,$82,$df,$74,$11,
                                   $03,$ea,$4f,$92,$1a,$44,$88,$0b,
                                   $9c,$21,$57,$a6,$64,$62,$6d,$1d,
                                   $ef,$9e,$a4,$20,$fd,$e6,$9b,$96,
                                   $74,$2a,$25,$f0,$54,$23,$40,$c7,
                                   $ba,$ef,$24,$ca,$84,$82,$bb,$09);

  ct_ctr : array[0..63] of byte = ($b8,$09,$14,$08,$77,$dd,$16,$c0,
                                   $76,$78,$09,$04,$f8,$3d,$ed,$11,
                                   $bb,$41,$e6,$4e,$9b,$f1,$76,$ce,
                                   $05,$d4,$18,$6b,$25,$86,$d4,$c9,
                                   $49,$e8,$2f,$dc,$5d,$6e,$78,$ab,
                                   $78,$13,$63,$e5,$17,$81,$fc,$9b,
                                   $73,$1a,$3c,$05,$83,$97,$9a,$92,
                                   $6e,$7f,$e0,$b8,$a2,$05,$ac,$29);

  ct_ofb : array[0..63] of byte = ($14,$f7,$64,$61,$87,$81,$7e,$b5,
                                   $86,$59,$91,$46,$b8,$2b,$d7,$19,
                                   $97,$32,$91,$71,$6c,$4d,$82,$d0,
                                   $1a,$07,$9e,$6d,$f7,$00,$e6,$eb,
                                   $0e,$f0,$60,$3e,$2e,$e5,$34,$c1,
                                   $74,$f4,$4a,$86,$78,$a0,$1f,$5b,
                                   $a9,$97,$8a,$35,$4c,$35,$c7,$a0,
                                   $52,$c3,$82,$18,$18,$3c,$be,$71);


var
  ct: array[0..63] of byte;

var
  Context: TCAMContext;


{---------------------------------------------------------------------------}
function test(px,py: pointer): string;
begin
  if compmem(px,py,64) then test := 'OK' else test := 'Error';
end;


{---------------------------------------------------------------------------}
procedure TestCFB;
var
  i: integer;
  pp,pc: pointer;
begin
  if CAM_CFB_Init(key128, 128, IV, context)<>0 then begin
    writeln('*** Error CFB');
    exit;
  end;
  pp := @plain;
  pc := @ct;
  for i:=1 to sizeof(plain) do begin
    if CAM_CFB_Encrypt(pp, pc, 1, context)<>0 then begin
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
  if CAM_CTR_Init(key128, 128, CTR, context)<>0 then begin
    writeln('*** Error CTR');
    exit;
  end;
  pp := @plain;
  pc := @ct;
  for i:=1 to sizeof(plain) do begin
    if CAM_CTR_Encrypt(pp, pc, 1, context)<>0 then begin
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
  if CAM_OFB_Init(key128, 128, IV, context)<>0 then begin
    writeln('*** Error OFB');
    exit;
  end;
  pp := @plain;
  pc := @ct;
  for i:=1 to sizeof(plain) do begin
    if CAM_OFB_Encrypt(pp, pc, 1, context)<>0 then begin
      writeln('*** Error OFB');
      exit;
    end;
    inc(Ptr2Inc(pp));
    inc(Ptr2Inc(pc));
  end;
  writeln('OFB  test: ', test(@ct,@ct_ofb));
end;


begin
  writeln('Test program "Associativity of Camellia CFB,OFB,CTR"   (C) 2008  W.Ehrhardt');
  CAM_SetFastInit(true);
  TestCFB;
  TestCTR;
  TestOFB;
end.
