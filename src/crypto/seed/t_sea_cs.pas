{-Test prog for Seed CTR Seek, (c) we July 2010}

program T_SEA_CS;

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
  HRTimer,
  {$ifdef USEDLL}
    {$ifdef VirtualPascal}
      SEA_Intv;
    {$else}
      SEA_Intf;
    {$endif}
  {$else}
    sea_base, sea_ctr;
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
  ctx1, ctx2: TSEAContext;
  Err : integer;

{$ifdef USE_INT64}
const
  BSIZE=$8000;
{$else}
const
  BSIZE=8192;
{$endif}



{---------------------------------------------------------------------------}
procedure My_IncMSBFull(var CTR: TSEABlock);
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
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);


     CTR : TSEABlock =            ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7,
                                   $f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

  plain  : array[0..63] of byte = ($6b,$c1,$be,$e2,$2e,$40,$9f,$96,
                                   $e9,$3d,$7e,$11,$73,$93,$17,$2a,
                                   $ae,$2d,$8a,$57,$1e,$03,$ac,$9c,
                                   $9e,$b7,$6f,$ac,$45,$af,$8e,$51,
                                   $30,$c8,$1c,$46,$a3,$5c,$e4,$11,
                                   $e5,$fb,$c1,$19,$1a,$0a,$52,$ef,
                                   $f6,$9f,$24,$45,$df,$4f,$9b,$17,
                                   $ad,$2b,$41,$7b,$e6,$6c,$37,$10);

  ct_ctr : array[0..63] of byte = ($8f,$a4,$8f,$2f,$0e,$74,$b5,$d5,
                                   $90,$55,$ad,$1d,$a6,$5a,$4e,$29,
                                   $3c,$c0,$39,$30,$81,$61,$fb,$1f,
                                   $3b,$64,$92,$0d,$0e,$fe,$e2,$46,
                                   $a1,$61,$4d,$63,$96,$a3,$ab,$25,
                                   $9e,$eb,$68,$96,$fb,$51,$aa,$27,
                                   $a6,$5e,$87,$35,$00,$9f,$25,$7b,
                                   $04,$d3,$82,$3f,$97,$bd,$02,$7e);


var
  ct: array[0..255] of byte;
  SO: integer;
begin

  writeln('Known vector test, 128 bit key');
  Err := SEA_CTR_Init(key128, 128, CTR, ctx2);
  CheckError;
  if userdef then begin
    Err := SEA_SetIncProc({$ifdef FPC_ProcVar}@{$endif}My_IncMSBFull, ctx2);
    CheckError;
  end;
  for SO:=0 to 63 do begin
    write('.');
    Err := SEA_CTR_Seek(CTR, SO, 0, ctx2);
    CheckError;
    Err := SEA_CTR_Encrypt(@plain[SO], @ct[SO], 1, ctx2);
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
     CTR : TSEABlock =            ($ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,
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
  Err := SEA_CTR_Init(key128, 128, CTR, ctx1);
  CheckError;
  case n of
    1: begin
         writeln('IncProc = SEA_IncMSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = SEA_IncMSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := SEA_SetIncProc(@SEA_IncMSBFull, ctx1);
         {$else}
           err := SEA_SetIncProc(SEA_IncMSBFull, ctx1);
         {$endif}
       end;
    2: begin
         writeln('IncProc = SEA_IncLSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = SEA_IncLSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := SEA_SetIncProc(@SEA_IncLSBFull, ctx1);
         {$else}
           err := SEA_SetIncProc(SEA_IncLSBFull, ctx1);
         {$endif}
       end;

    3: begin
         writeln('IncProc = SEA_IncMSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = SEA_IncMSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := SEA_SetIncProc(@SEA_IncMSBPart, ctx1);
         {$else}
           err := SEA_SetIncProc(SEA_IncMSBPart, ctx1);
         {$endif}
       end;

    4: begin
         writeln('IncProc = SEA_IncLSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = SEA_IncLSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := SEA_SetIncProc(@SEA_IncLSBPart, ctx1);
         {$else}
           err := SEA_SetIncProc(SEA_IncLSBPart, ctx1);
         {$endif}
       end;
  end;

  CheckError;
  ofs := 0;
  ReStartTimer(HR);
  repeat
    for i:=1 to 99 do begin
      Err := SEA_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
      ofs := ofs + BSIZE;
    end;
    {$ifdef USE_INT64}
      write(erroutput, 100.0*ofs/oma:1:3,'%'#13);
    {$else}
      write(100.0*ofs/oma:1:3,'%'#13);
    {$endif}
    Err := SEA_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
    CheckError;
    i := random(BSIZE);
    Err := SEA_CTR_Init(key128, 128, CTR, ctx2);
    CheckError;
    case n of
      1: begin
           {$ifdef FPC_ProcVar}
             err := SEA_SetIncProc(@SEA_IncMSBFull, ctx2);
           {$else}
             err := SEA_SetIncProc(SEA_IncMSBFull, ctx2);
           {$endif}
         end;
      2: begin
           {$ifdef FPC_ProcVar}
             err := SEA_SetIncProc(@SEA_IncLSBFull, ctx2);
           {$else}
             err := SEA_SetIncProc(SEA_IncLSBFull, ctx2);
           {$endif}
         end;

      3: begin
           {$ifdef FPC_ProcVar}
             err := SEA_SetIncProc(@SEA_IncMSBPart, ctx2);
           {$else}
             err := SEA_SetIncProc(SEA_IncMSBPart, ctx2);
           {$endif}
         end;

      4: begin
           {$ifdef FPC_ProcVar}
             err := SEA_SetIncProc(@SEA_IncLSBPart, ctx2);
           {$else}
             err := SEA_SetIncProc(SEA_IncLSBPart, ctx2);
           {$endif}
         end;
      else begin
             writeln('Invalid n');
             halt;
           end;
    end;
    CheckError;
    {$ifdef USE_INT64}
      Err := SEA_CTR_Seek64(CTR, ofs+i, ctx2);
    {$else}
      Err := SEA_CTR_Seek(CTR, ofs+i, 0, ctx2);
    {$endif}
    CheckError;
    Err := SEA_CTR_Encrypt(@pbuf[i], @cbuf2[i], 1, ctx2);
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
  writeln('Test program "SEA CTR Seek"    (C) 2010  W.Ehrhardt');
  {$ifdef USEDLL}
    writeln('DLL Version: ',SEA_DLL_Version);
  {$endif}
  writeln;
  writeln('Test using standard SEA_IncMSBFull');
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
