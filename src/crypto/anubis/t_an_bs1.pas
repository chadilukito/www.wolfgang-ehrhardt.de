{-Test program for basic Anubis functions, (c) we Aug.2008}
program t_an_bs1;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  mem_util,anu_base;


{$ifdef StrictLong}
  {$warnings off}
  {$R-} {avoid D9+ errors!}
{$endif}



{$ifdef StrictLong}
  {$warnings on}
  {$ifdef RangeChecks_on}
    {$R+}
  {$endif}
{$endif}
const
  key128 : array[0..15] of byte  = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);

  plain  : array[0..63] of char8 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  ct_ecb : array[0..63] of byte  = ($b2,$cb,$8d,$46,$4c,$71,$41,$b6,
                                    $b3,$68,$04,$ce,$7d,$2b,$3f,$7f,
                                    $60,$86,$f0,$9a,$db,$f4,$db,$95,
                                    $2b,$b5,$42,$99,$91,$31,$d1,$fd,
                                    $0f,$a5,$62,$7d,$0e,$35,$c7,$4d,
                                    $d9,$cd,$52,$b7,$ce,$46,$d3,$4a,
                                    $94,$d3,$86,$a0,$4c,$3b,$cb,$9b,
                                    $7b,$d2,$3d,$bb,$84,$89,$9a,$a4);


var
  ctx: TANUContext;
  i,j: integer;
  ct: array[0..63] of byte;
  bi,bo,b2 : TANUBlock;
begin
  writeln('offset T0 mod 15 = ', ANU_T0ofs);
  HexUpper := true;
  move(plain, bi, 16);
  writeln(ANU_Init_Encr(Key128, 128, ctx));
  writeln('KeyEnc');
  for i:=0 to ctx.rounds-1 do begin
    for j:=0 to 3 do begin
      write(HexLong(ctx.RK[i][j]), '  ')
    end;
    writeln;
  end;
  ANU_Encrypt(ctx, BI, BO);
  writeln('Enc: ',compmem(@BO,@ct_ecb,16));

  writeln('KeyDec');
  writeln(ANU_Init_Decr(Key128, 128, ctx));
  for i:=0 to ctx.rounds-1 do begin
    for j:=0 to 3 do begin
      write(HexLong(ctx.RK[i][j]), '  ')
    end;
    writeln;
  end;
  ANU_Decrypt(ctx, BO, B2);
  writeln('Dec: ',compmem(@B2,@plain,16));
end.
