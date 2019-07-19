{-Test prog for XTEA CTR Seek, (c) we July 2010}

program T_SE_CSK;

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
  HRTimer, BTypes,
  {$ifdef USEDLL}
    {$ifdef VirtualPascal}
      XT_Intv;
    {$else}
      XT_Intf;
    {$endif}
  {$else}
    XT_base, XT_ctr;
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

var
  ctx1, ctx2: TXTContext;
  Err : integer;

{$ifdef USE_INT64}
const
  BSIZE=$8000;
{$else}
const
  BSIZE=8192;
{$endif}



{---------------------------------------------------------------------------}
procedure My_IncMSBFull(var CTR: TXTBlock);
{$ifdef USEDLL} stdcall; {$endif}
  {-Increment CTR[7]..CTR[0]}
var
  j: integer;
begin
  {This is the same as the standard pre-defined function, but it cannot be }
  {recognized by its @address and therefore the seek loop will be performed}
  for j:=7 downto 0 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;


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
const
  key128 : array[0..15] of byte = ($78,$56,$34,$12,$f0,$cd,$cb,$9a,
                                   $48,$37,$26,$15,$c0,$bf,$ae,$9d);

     CTR : TXTBlock             = ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7);

  plain  : array[0..63] of byte = ($01,$02,$03,$04,$05,$06,$07,$08,
                                   $11,$12,$13,$14,$15,$16,$17,$18,
                                   $21,$22,$23,$24,$25,$26,$27,$28,
                                   $31,$32,$33,$34,$35,$36,$37,$38,
                                   $41,$42,$43,$44,$45,$46,$47,$48,
                                   $51,$52,$53,$54,$55,$56,$57,$58,
                                   $61,$62,$63,$64,$65,$66,$67,$68,
                                   $71,$72,$73,$74,$75,$76,$77,$78);

  ct_ctr: array[0.. 63] of byte = ($21,$a3,$e4,$bf,$7f,$12,$aa,$32,
                                   $b8,$75,$62,$18,$42,$62,$9f,$ab,
                                   $94,$72,$7d,$8a,$00,$d4,$61,$e5,
                                   $55,$1e,$5b,$db,$6c,$03,$4b,$b8,
                                   $fc,$5f,$0a,$ea,$f8,$b2,$31,$53,
                                   $f0,$9c,$cd,$e9,$de,$56,$b5,$f5,
                                   $a2,$22,$0b,$92,$8a,$7c,$a3,$87,
                                   $06,$5e,$bf,$cf,$ff,$b2,$19,$3c);

var
  ct: array[0..255] of byte;
  SO: integer;
begin

  writeln('Known vector test, 128 bit key');
  Err := XT_CTR_Init(key128, sizeof(key128), CTR, ctx2);
  CheckError;
  if userdef then begin
    Err := XT_SetIncProc({$ifdef FPC_ProcVar}@{$endif}My_IncMSBFull, ctx2);
    CheckError;
  end;
  for SO:=0 to 63 do begin
    write('.');
    Err := XT_CTR_Seek(CTR, SO, 0, ctx2);
    CheckError;
    Err := XT_CTR_Encrypt(@plain[SO], @ct[SO], 1, ctx2);
    if ct[SO]<>ct_ctr[SO] then begin
      writeln('Diff:  SO=',SO:2,'  ct_ctr[SO]=',ct_ctr[SO]:3,'  ct[SO]=',ct[SO]:3);
    end;
  end;
  writeln(' done');
end;


{---------------------------------------------------------------------------}
procedure bigtest(n: integer);
const
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);
     CTR : TXTBlock             = ($f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

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
  Err := XT_CTR_Init(key128, sizeof(key128), CTR, ctx1);
  CheckError;
  case n of
    1: begin
         writeln('IncProc = XT_IncMSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = XT_IncMSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := XT_SetIncProc(@XT_IncMSBFull, ctx1);
         {$else}
           err := XT_SetIncProc(XT_IncMSBFull, ctx1);
         {$endif}
       end;
    2: begin
         writeln('IncProc = XT_IncLSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = XT_IncLSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := XT_SetIncProc(@XT_IncLSBFull, ctx1);
         {$else}
           err := XT_SetIncProc(XT_IncLSBFull, ctx1);
         {$endif}
       end;

    3: begin
         writeln('IncProc = XT_IncMSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = XT_IncMSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := XT_SetIncProc(@XT_IncMSBPart, ctx1);
         {$else}
           err := XT_SetIncProc(XT_IncMSBPart, ctx1);
         {$endif}
       end;

    4: begin
         writeln('IncProc = XT_IncLSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = XT_IncLSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := XT_SetIncProc(@XT_IncLSBPart, ctx1);
         {$else}
           err := XT_SetIncProc(XT_IncLSBPart, ctx1);
         {$endif}
       end;
  end;

  CheckError;
  ofs := 0;
  ReStartTimer(HR);
  repeat
    for i:=1 to 99 do begin
      Err := XT_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
      ofs := ofs + BSIZE;
    end;
    {$ifdef USE_INT64}
      write(erroutput, 100.0*ofs/oma:1:3,'%'#13);
    {$else}
      write(100.0*ofs/oma:1:3,'%'#13);
    {$endif}
    Err := XT_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
    CheckError;
    i := random(BSIZE);
    Err := XT_CTR_Init(key128, sizeof(key128), CTR, ctx2);
    CheckError;
    case n of
      1: begin
           {$ifdef FPC_ProcVar}
             err := XT_SetIncProc(@XT_IncMSBFull, ctx2);
           {$else}
             err := XT_SetIncProc(XT_IncMSBFull, ctx2);
           {$endif}
         end;
      2: begin
           {$ifdef FPC_ProcVar}
             err := XT_SetIncProc(@XT_IncLSBFull, ctx2);
           {$else}
             err := XT_SetIncProc(XT_IncLSBFull, ctx2);
           {$endif}
         end;

      3: begin
           {$ifdef FPC_ProcVar}
             err := XT_SetIncProc(@XT_IncMSBPart, ctx2);
           {$else}
             err := XT_SetIncProc(XT_IncMSBPart, ctx2);
           {$endif}
         end;

      4: begin
           {$ifdef FPC_ProcVar}
             err := XT_SetIncProc(@XT_IncLSBPart, ctx2);
           {$else}
             err := XT_SetIncProc(XT_IncLSBPart, ctx2);
           {$endif}
         end;
      else begin
             writeln('Invalid n');
             halt;
           end;
    end;
    CheckError;
    {$ifdef USE_INT64}
      Err := XT_CTR_Seek64(CTR, ofs+i, ctx2);
    {$else}
      Err := XT_CTR_Seek(CTR, ofs+i, 0, ctx2);
    {$endif}
    CheckError;
    Err := XT_CTR_Encrypt(@pbuf[i], @cbuf2[i], 1, ctx2);
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
  writeln('Test program "XT CTR Seek"    (C) 2010  W.Ehrhardt');
  {$ifdef USEDLL}
    writeln('DLL Version: ',XT_DLL_Version);
  {$endif}
  writeln;
  writeln('Test using standard XT_IncMSBFull');
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
