{Test program for basic Camellia functions, (c) we 06.2008}

program t_ca_bas;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  mem_util,CAM_base;

const

  Key0: array[0..31] of byte = ($01,$23,$45,$67,$89,$ab,$cd,$ef,$fe,$dc,$ba,$98,$76,$54,$32,$10,
                                $00,$11,$22,$33,$44,$55,$66,$77,$88,$99,$aa,$bb,$cc,$dd,$ee,$ff);

   pt0: TCAMBlock = ($01,$23,$45,$67,$89,$ab,$cd,$ef,$fe,$dc,$ba,$98,$76,$54,$32,$10);
  c128: TCAMBlock = ($67,$67,$31,$38,$54,$96,$69,$73,$08,$57,$06,$56,$48,$ea,$be,$43);
  c192: TCAMBlock = ($b4,$99,$34,$01,$b3,$e9,$96,$f8,$4e,$e5,$ce,$e7,$d7,$9b,$09,$b9);
  c256: TCAMBlock = ($9a,$cc,$23,$7d,$ff,$16,$d7,$6c,$20,$ef,$7c,$91,$9e,$3a,$75,$09);

var
  ctx: TCAMContext;
  ct0: TCAMBlock;
  pt : TCAMBlock;
  i: integer;
begin
  writeln('Key size = 128');
  i := CAM_Init(Key0, 128, ctx);
  if i<>0 then begin
    writeln('CAM_Init: ',i);
    exit;
  end;
  CAM_Encrypt(ctx, pt0, ct0);
  writeln('Encrypt: ', CompMem(@ct0, @c128, sizeof(ct0)));

  i := CAM_Init(Key0, 128, ctx);
  if i<>0 then begin
    writeln('CAM_Init: ',i);
    exit;
  end;

  CAM_Decrypt(ctx, c128, pt);
  writeln('Decrypt: ', CompMem(@pt0, @pt, sizeof(pt0)));
  {
  for i:=0 to 271 do begin
    write(ctx.ek[i]:4);
    if i and 7 = 7 then writeln;
  end;
  }
  writeln('Key size = 192');
  i := CAM_Init(Key0, 192, ctx);
  if i<>0 then begin
    writeln('CAM_Init: ',i);
    exit;
  end;
  CAM_Encrypt(ctx, pt0, ct0);
  writeln('Encrypt: ', CompMem(@ct0, @c192, sizeof(ct0)));

  i := CAM_Init(Key0, 192, ctx);
  if i<>0 then begin
    writeln('CAM_Init: ',i);
    exit;
  end;
  CAM_Decrypt(ctx, c192, pt);
  writeln('Decrypt: ', CompMem(@pt0, @pt, sizeof(pt0)));
  {
  for i:=0 to 271 do begin
    write(ctx.ek[i]:4);
    if i and 7 = 7 then writeln;
  end;
  }
  writeln('Key size = 256');
  i := CAM_Init(Key0, 256, ctx);
  if i<>0 then begin
    writeln('CAM_Init: ',i);
    exit;
  end;
  CAM_Encrypt(ctx, pt0, ct0);

  writeln('Encrypt: ', CompMem(@ct0, @c256, sizeof(ct0)));
  i := CAM_Init(Key0, 256, ctx);
  if i<>0 then begin
    writeln('CAM_Init: ',i);
    exit;
  end;
  CAM_Decrypt(ctx, c256, pt);
  writeln('Decrypt: ', CompMem(@pt0, @pt, sizeof(pt0)));
  {
  for i:=0 to 271 do begin
    write(ctx.ek[i]:4);
    if i and 7 = 7 then writeln;
  end;
  }
end.
