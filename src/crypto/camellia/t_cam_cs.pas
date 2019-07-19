{-Test prog for CAM CTR Seek, (c) we July 2010}

program T_CAM_CS;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifdef BIT16}
{$N+,F+}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  HRTimer, Mem_Util,
  {$ifdef USEDLL}
    {$ifdef VirtualPascal}
      CAM_Intv;
    {$else}
      CAM_Intf;
    {$endif}
  {$else}
    cam_base, cam_ctr;
  {$endif}

{USE_INT64: if Int64 and errout available}

{$ifdef FPC}
  {$ifdef VER2}
    {$define USE_INT64}
  {$endif}
{$endif}
{$ifdef CONDITIONALEXPRESSIONS}  {D6+}
  {$define USE_INT64}
{$endif}

var
  HR: THRTimer;

{---------------------------------------------------------------------------}
procedure My_IncMSBFull(var CTR: TCAMBlock);
{$ifdef USEDLL} stdcall; {$endif}
  {-Increment CTR[15]..CTR[0]}
var
  j: integer;
begin
  {This is the same as the standard pre-defined function, but it cannot be }
  {recognized by its @address and therefore the seek loop will be performed}
  for j:=15 downto 0 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;



var
  ctx1, ctx2: TCAMContext;
  Err : integer;

{$ifdef USE_INT64}
const
  BSIZE=$8000;
{$else}
const
  BSIZE=8192;
{$endif}

var
  pbuf, cbuf1, cbuf2: array[0..BSIZE-1] of byte;

{---------------------------------------------------------------------------}
procedure CheckError;
begin
  if Err<>0 then begin
    writeln('Error ',Err);
    halt;
  end;
end;


{---------------------------------------------------------------------------}
procedure randomtest(userdef: boolean);
  {-Camellia CTR test vectors #3, #6, #9 from RFC5528}
const
  key128 : array[0..15] of byte = ($76,$91,$be,$03,$5e,$50,$20,$a8,
                                   $ac,$6e,$61,$85,$29,$f9,$a0,$dc);
  key192 : array[0..23] of byte = ($02,$bf,$39,$1e,$e8,$ec,$b1,$59,
                                   $b9,$59,$61,$7b,$09,$65,$27,$9b,
                                   $f5,$9b,$60,$a7,$86,$d3,$e0,$fe);
  key256 : array[0..31] of byte = ($ff,$7a,$61,$7c,$e6,$91,$48,$e4,
                                   $f1,$72,$6e,$2f,$43,$58,$1d,$e2,
                                   $aa,$62,$d9,$f8,$05,$53,$2e,$df,
                                   $f1,$ee,$d6,$87,$fb,$54,$15,$3d);

  plain  : array[0..35] of byte = ($00,$01,$02,$03,$04,$05,$06,$07,
                                   $08,$09,$0a,$0b,$0c,$0d,$0e,$0f,
                                   $10,$11,$12,$13,$14,$15,$16,$17,
                                   $18,$19,$1a,$1b,$1c,$1d,$1e,$1f,
                                   $20,$21,$22,$23);

     ct1 : array[0..35] of byte = ($b1,$9d,$1f,$cd,$cb,$75,$eb,$88,
                                   $2f,$84,$9c,$e2,$4d,$85,$cf,$73,
                                   $9c,$e6,$4b,$2b,$5c,$9d,$73,$f1,
                                   $4f,$2d,$5d,$9d,$ce,$98,$89,$cd,
                                   $df,$50,$86,$96);
     ct2 : array[0..35] of byte = ($57,$10,$e5,$56,$e1,$48,$7a,$20,
                                   $b5,$ac,$0e,$73,$f1,$9e,$4e,$78,
                                   $76,$f3,$7f,$dc,$91,$b1,$ef,$4d,
                                   $4d,$ad,$e8,$e6,$66,$a6,$4d,$0e,
                                   $d5,$57,$ab,$57);
     ct3 : array[0..35] of byte = ($a4,$da,$23,$fc,$e6,$a5,$ff,$aa,
                                   $6d,$64,$ae,$9a,$06,$52,$a4,$2c,
                                   $d1,$61,$a3,$4b,$65,$f9,$67,$9f,
                                   $75,$c0,$1f,$10,$1f,$71,$27,$6f,
                                   $15,$ef,$0d,$8d);

    ctr1 : TCAMBlock = ($00,$e0,$01,$7b,$27,$77,$7f,$3f,$4a,$17,$86,$f0,$00,$00,$00,$01);
    ctr2 : TCAMBlock = ($00,$07,$bd,$fd,$5c,$bd,$60,$27,$8d,$cc,$09,$12,$00,$00,$00,$01);
    ctr3 : TCAMBlock = ($00,$1c,$c5,$b7,$51,$a5,$1d,$70,$a1,$c1,$11,$48,$00,$00,$00,$01);

var
  ct: array[0..255] of byte;
  SO: integer;
begin

  writeln('RFC5528 vector #3 test: 128 bit key');
  Err := CAM_CTR_Init(key128, 128, ctr1, ctx2);
  CheckError;
  if userdef then begin
    Err := CAM_SetIncProc({$ifdef FPC_ProcVar}@{$endif}My_IncMSBFull, ctx2);
    CheckError;
  end;
  for SO:=0 to 35 do begin
    write('.');
    Err := CAM_CTR_Seek(ctr1, SO, 0, ctx2);
    CheckError;
    Err := CAM_CTR_Encrypt(@plain[SO], @ct[SO], 1, ctx2);
    if ct[SO]<>ct1[SO] then begin
      writeln('Diff:  SO=',SO:2,'  ct1[SO]=',ct1[SO]:3,'  ct[SO]=',ct[SO]:3);
    end;
  end;
  writeln(' done');

  writeln('RFC5528 vector #6 test: 192 bit key');
  Err := CAM_CTR_Init(key192, 192, ctr2, ctx2);
  CheckError;
  if userdef then begin
    Err := CAM_SetIncProc({$ifdef FPC_ProcVar}@{$endif}My_IncMSBFull, ctx2);
    CheckError;
  end;
  for SO:=0 to 35 do begin
    write('.');
    {$ifdef USE_INT64}
      Err := CAM_CTR_Seek64(ctr2, SO, ctx2);
    {$else}
      Err := CAM_CTR_Seek(ctr2, SO, 0, ctx2);
    {$endif}
    CheckError;
    Err := CAM_CTR_Encrypt(@plain[SO], @ct[SO], 1, ctx2);
    if ct[SO]<>ct2[SO] then begin
      writeln('Diff:  SO=',SO:2,'  ct2[SO]=',ct2[SO]:3,'  ct[SO]=',ct[SO]:3);
    end;
  end;
  writeln(' done');

  writeln('RFC5528 vector #9 test: 256 bit key');
  Err := CAM_CTR_Init(key256, 256, ctr3, ctx2);
  CheckError;
  if userdef then begin
    Err := CAM_SetIncProc({$ifdef FPC_ProcVar}@{$endif}My_IncMSBFull, ctx2);
    CheckError;
  end;
  for SO:=35 downto 0 do begin
    write('.');
    Err := CAM_CTR_Seek(ctr3, SO, 0, ctx2);
    CheckError;
    Err := CAM_CTR_Encrypt(@plain[SO], @ct[SO], 1, ctx2);
    if ct[SO]<>ct3[SO] then begin
      writeln('Diff:  SO=',SO:2,'  ct3[SO]=',ct2[SO]:3,'  ct[SO]=',ct[SO]:3);
    end;
  end;
  writeln(' done');
end;


{---------------------------------------------------------------------------}
procedure bigtest(n: integer);
const
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);
     CTR : TCAMBlock =            ($ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,
                                   $ff,$ff,$ff,$ff,$fd,$fc,$fb,$fa);

{$ifdef USE_INT64}
var
  ofs: int64;
const
  oma = int64($3FFFFFFF)*$100;  {avoid braindamaged D2 error}
{$else}
var
  ofs: longint;
const
  oma = $6FFFFFFF;
{$endif}
var
  i: integer;
begin
  for i:=0 to BSIZE-1 do pbuf[i] := random(256);
  Err := CAM_CTR_Init(key128, 128, CTR, ctx1);
  CheckError;
  case n of
    1: begin
         writeln('IncProc = CAM_IncMSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = CAM_IncMSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := CAM_SetIncProc(@CAM_IncMSBFull, ctx1);
         {$else}
           err := CAM_SetIncProc(CAM_IncMSBFull, ctx1);
         {$endif}
       end;
    2: begin
         writeln('IncProc = CAM_IncLSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = CAM_IncLSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := CAM_SetIncProc(@CAM_IncLSBFull, ctx1);
         {$else}
           err := CAM_SetIncProc(CAM_IncLSBFull, ctx1);
         {$endif}
       end;

    3: begin
         writeln('IncProc = CAM_IncMSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = CAM_IncMSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := CAM_SetIncProc(@CAM_IncMSBPart, ctx1);
         {$else}
           err := CAM_SetIncProc(CAM_IncMSBPart, ctx1);
         {$endif}
       end;

    4: begin
         writeln('IncProc = CAM_IncLSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = CAM_IncLSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := CAM_SetIncProc(@CAM_IncLSBPart, ctx1);
         {$else}
           err := CAM_SetIncProc(CAM_IncLSBPart, ctx1);
         {$endif}
       end;
  end;

  CheckError;
  ofs := 0;
  ReStartTimer(HR);
  repeat
    for i:=1 to 99 do begin
      Err := CAM_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
      ofs := ofs + BSIZE;
    end;
    {$ifdef USE_INT64}
      write(erroutput, 100.0*ofs/oma:1:3,'%'#13);
    {$else}
      write(100.0*ofs/oma:1:3,'%'#13);
    {$endif}
    Err := CAM_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
    CheckError;
    i := random(BSIZE);
    Err := CAM_CTR_Init(key128, 128, CTR, ctx2);
    CheckError;
    case n of
      1: begin
           {$ifdef FPC_ProcVar}
             err := CAM_SetIncProc(@CAM_IncMSBFull, ctx2);
           {$else}
             err := CAM_SetIncProc(CAM_IncMSBFull, ctx2);
           {$endif}
         end;
      2: begin
           {$ifdef FPC_ProcVar}
             err := CAM_SetIncProc(@CAM_IncLSBFull, ctx2);
           {$else}
             err := CAM_SetIncProc(CAM_IncLSBFull, ctx2);
           {$endif}
         end;

      3: begin
           {$ifdef FPC_ProcVar}
             err := CAM_SetIncProc(@CAM_IncMSBPart, ctx2);
           {$else}
             err := CAM_SetIncProc(CAM_IncMSBPart, ctx2);
           {$endif}
         end;

      4: begin
           {$ifdef FPC_ProcVar}
             err := CAM_SetIncProc(@CAM_IncLSBPart, ctx2);
           {$else}
             err := CAM_SetIncProc(CAM_IncLSBPart, ctx2);
           {$endif}
         end;
      else begin
             writeln('Invalid n');
             halt;
           end;
    end;
    CheckError;
    {$ifdef USE_INT64}
      Err := CAM_CTR_Seek64(CTR, ofs+i, ctx2);
    {$else}
      Err := CAM_CTR_Seek(CTR, ofs+i, 0, ctx2);
    {$endif}
    CheckError;
    Err := CAM_CTR_Encrypt(@pbuf[i], @cbuf2[i], 1, ctx2);
    CheckError;
    if cbuf1[i]<>cbuf2[i] then begin
      writeln('Diff:  Offset=',ofs+i,'  cbuf1[]=',cbuf1[i]:3,'  cbuf2[]=',cbuf2[i]:3);
      halt;
    end;
    ofs := ofs + BSIZE;
  until ofs>oma;
  writeln('Done - no differences.');
  writeln('Time [s]: ', ReadSeconds(HR):1:3);
end;

var
  {$ifdef D12Plus}
    s: string;
  {$else}
    s: string[10];
  {$endif}
begin
  writeln('Test program "Camellia CTR Seek"    (C) 2010  W.Ehrhardt');
  {$ifdef USEDLL}
    writeln('Using CAM_DLL V',CAM_DLL_Version);
  {$endif}
  writeln;
  writeln('Test using standard CAM_IncMSBFull');
  randomtest(false);
  writeln;
  writeln('Test using user-defines My_IncMSBFull');
  randomtest(true);
  writeln;
  StartTimer(HR);
  s := paramstr(1);
  if s='big' then begin
    bigtest(1);
    bigtest(2);
    bigtest(3);
    bigtest(4);
  end;
end.
