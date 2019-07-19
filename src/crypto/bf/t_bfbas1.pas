{-Test prog for Blowfish basic routines, we 11.2004}

program T_bfbas1;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  bf_base,mem_util;

var
  ctx: TBFContext;

{Test vectors by Eric Young from http://www.schneier.com/code/vectors.txt}

const
  k1: TBFBlock = ($00, $00, $00, $00, $00, $00, $00, $00);
  p1: TBFBlock = ($00, $00, $00, $00, $00, $00, $00, $00);
  c1: TBFBlock = ($4E, $F9, $97, $45, $61, $98, $DD, $78);

  k2: TBFBlock = ($FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF);
  p2: TBFBlock = ($FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF);
  c2: TBFBlock = ($51, $86, $6F, $D5, $B8, $5E, $CB, $8A);

  k3: TBFBlock = ($30, $00, $00, $00, $00, $00, $00, $00);
  p3: TBFBlock = ($10, $00, $00, $00, $00, $00, $00, $01);
  c3: TBFBlock = ($7D, $85, $6F, $9A, $61, $30, $63, $F2);


procedure InitError;
begin
  writeln('BF_Init error');
  halt;
end;

var
  ct: TBFBlock;
begin
  if BF_Init(k1, 8, ctx)<>0 then InitError;
  BF_Encrypt(ctx, p1, ct);
  writeln('1 E: ', CompMem(@ct, @c1, sizeof(ct)));
  BF_Decrypt(ctx, c1, ct);
  writeln('1 D: ', CompMem(@ct, @p1, sizeof(ct)));

  if BF_Init(k2, 8, ctx)<>0 then InitError;
  BF_Encrypt(ctx, p2, ct);
  writeln('2 E: ', CompMem(@ct, @c2, sizeof(ct)));
  BF_Decrypt(ctx, c2, ct);
  writeln('2 D: ', CompMem(@ct, @p2, sizeof(ct)));

  if BF_Init(k3, 8, ctx)<>0 then InitError;
  BF_Encrypt(ctx, p3, ct);
  writeln('3 E: ', CompMem(@ct, @c3, sizeof(ct)));
  BF_Decrypt(ctx, c3, ct);
  writeln('3 D: ', CompMem(@ct, @p3, sizeof(ct)));

end.
