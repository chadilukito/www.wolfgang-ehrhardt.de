{-Test prog for SHACAL2 basic routines, we Jan.2005}

program T_SCBas1;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}


uses SC_Base,mem_util;

var
  ctx: TSCContext;


{NESSIE submission file shacal2testvectors1-4.txt, Set 1, vector# 0}

const k1: array[0.. 63] of byte = ($80,$00,$00,$00,$00,$00,$00,$00,
                                   $00,$00,$00,$00,$00,$00,$00,$00,
                                   $00,$00,$00,$00,$00,$00,$00,$00,
                                   $00,$00,$00,$00,$00,$00,$00,$00,
                                   $00,$00,$00,$00,$00,$00,$00,$00,
                                   $00,$00,$00,$00,$00,$00,$00,$00,
                                   $00,$00,$00,$00,$00,$00,$00,$00,
                                   $00,$00,$00,$00,$00,$00,$00,$00);


const p1: TSCBlock = ($00,$00,$00,$00,$00,$00,$00,$00,
                      $00,$00,$00,$00,$00,$00,$00,$00,
                      $00,$00,$00,$00,$00,$00,$00,$00,
                      $00,$00,$00,$00,$00,$00,$00,$00);


const c1: TSCBlock = ($36,$1a,$b6,$32,$2f,$a9,$e7,$a7,
                      $bb,$23,$81,$8d,$83,$9e,$01,$bd,
                      $da,$fd,$f4,$73,$05,$42,$6e,$dd,
                      $29,$7a,$ed,$b9,$f6,$20,$2b,$ae);


procedure InitError;
begin
  writeln('SC_Init error');
  halt;
end;

var
  ct: TSCBlock;
begin
  if SC_Init(k1, sizeof(k1), ctx)<>0 then InitError;
  SC_Encrypt(ctx, p1, ct);
  writeln('1 E: ', CompMem(@ct, @c1, sizeof(ct)));
  SC_Decrypt(ctx, c1, ct);
  writeln('1 D: ', CompMem(@ct, @p1, sizeof(ct)));
end.
