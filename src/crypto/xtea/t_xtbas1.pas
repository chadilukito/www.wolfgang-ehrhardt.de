{-Test prog for XTEA basic routines, we Jan.2005}

program t_xtbas1;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}


uses XT_base,mem_util;

var
  ctx: TXTContext;


{First vector set from tv_xtea.dat}

const
  p1: TXTBlock = ($01,$23,$45,$67,$89,$ab,$cd,$ef);
  c1: TXTBlock = ($b8,$bf,$28,$21,$62,$2b,$5b,$30);
  k1: array[0..15] of byte = ($00,$11,$22,$33,$44,$55,$66,$77,$88,$99,$aa,$bb,$cc,$dd,$ee,$ff);

var
  ct: TXTBlock;
begin
  if XT_Init(k1, sizeof(k1), ctx)<>0 then begin
    writeln('XT_Init error');
    halt;
  end;
  XT_Encrypt(ctx, p1, ct);
  writeln('Encrypt: ', CompMem(@ct, @c1, sizeof(ct)));
  XT_Decrypt(ctx, c1, ct);
  writeln('Decrypt: ', CompMem(@ct, @p1, sizeof(ct)));
end.
