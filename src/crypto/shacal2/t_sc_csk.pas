{-Test prog for Shacal-2 CTR Seek, (c) we Aug 2010}

program T_SC_CSK;

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
      SC_Intv;
    {$else}
      SC_Intf;
    {$endif}
  {$else}
    SC_base, SC_ctr;
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
  ctx1, ctx2: TSCContext;
  Err: integer;
  HR: THRTimer;

{$ifdef USE_INT64}
const
  BSIZE=$8000;
{$else}
const
  BSIZE=8192;
{$endif}



{---------------------------------------------------------------------------}
procedure My_IncMSBFull(var CTR: TSCBlock);
{$ifdef USEDLL} stdcall; {$endif}
  {-Increment CTR[31]..CTR[0]}
var
  j: integer;
begin
  {This is the same as the standard pre-defined function, but it cannot be }
  {recognized by its @address and therefore the seek loop will be performed}
  for j:=31 downto 0 do begin
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
  key   : array[0.. 63] of byte = ($32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32);
  CTR   : TSCBlock =              ($42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42);

  plain : array[0..127] of char8= '1111111111111111111111111111111122222222222222222222222222222222'+
                                  '3333333333333333333333333333333344444444444444444444444444444444';

  ct_ctr: array[0..127] of byte = ($45,$9b,$ff,$59,$c9,$31,$8b,$08,
                                   $ef,$b9,$d6,$62,$9f,$bc,$7a,$6a,
                                   $1b,$b3,$64,$f1,$ce,$c2,$b9,$22,
                                   $17,$10,$c1,$48,$f1,$ea,$3a,$66,
                                   $22,$4d,$3f,$52,$1a,$e7,$2b,$52,
                                   $07,$e4,$c7,$96,$c6,$cb,$7b,$3f,
                                   $05,$49,$ca,$d0,$58,$02,$d8,$4a,
                                   $7c,$3e,$fe,$c5,$a6,$00,$d6,$72,
                                   $6d,$80,$91,$60,$25,$6b,$96,$3b,
                                   $ae,$ee,$2c,$82,$cb,$ad,$c6,$2b,
                                   $1a,$ca,$ac,$9f,$be,$e7,$ce,$1a,
                                   $6b,$bf,$db,$d6,$3b,$8b,$ae,$97,
                                   $71,$a4,$b2,$8f,$05,$58,$7e,$e0,
                                   $6b,$30,$37,$70,$88,$36,$4a,$c4,
                                   $54,$b3,$b3,$00,$02,$9f,$ff,$83,
                                   $05,$e6,$40,$59,$49,$d6,$24,$ec);

var
  ct: array[0..255] of byte;
  SO: integer;
begin

  writeln('Known vector test, 256 bit key');
  Err := SC_CTR_Init(key, sizeof(key), CTR, ctx2);
  CheckError;
  if userdef then begin
    Err := SC_SetIncProc({$ifdef FPC_ProcVar}@{$endif}My_IncMSBFull, ctx2);
    CheckError;
  end;
  for SO:=0 to 127 do begin
    if odd(SO) then write('.');
    Err := SC_CTR_Seek(CTR, SO, 0, ctx2);
    CheckError;
    Err := SC_CTR_Encrypt(@plain[SO], @ct[SO], 1, ctx2);
    if ct[SO]<>ct_ctr[SO] then begin
      writeln('Diff:  SO=',SO:2,'  ct_ctr[SO]=',ct_ctr[SO]:3,'  ct[SO]=',ct[SO]:3);
    end;
  end;
  writeln(' done');
end;


{---------------------------------------------------------------------------}
procedure bigtest(n: integer);
const
  key   : array[0.. 63] of byte = ($32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32);
  CTR   : TSCBlock =              ($42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42);

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
  Err := SC_CTR_Init(key, sizeof(key), CTR, ctx1);
  CheckError;
  case n of
    1: begin
         writeln('IncProc = SC_IncMSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = SC_IncMSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := SC_SetIncProc(@SC_IncMSBFull, ctx1);
         {$else}
           err := SC_SetIncProc(SC_IncMSBFull, ctx1);
         {$endif}
       end;
    2: begin
         writeln('IncProc = SC_IncLSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = SC_IncLSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := SC_SetIncProc(@SC_IncLSBFull, ctx1);
         {$else}
           err := SC_SetIncProc(SC_IncLSBFull, ctx1);
         {$endif}
       end;

    3: begin
         writeln('IncProc = SC_IncMSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = SC_IncMSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := SC_SetIncProc(@SC_IncMSBPart, ctx1);
         {$else}
           err := SC_SetIncProc(SC_IncMSBPart, ctx1);
         {$endif}
       end;

    4: begin
         writeln('IncProc = SC_IncLSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = SC_IncLSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := SC_SetIncProc(@SC_IncLSBPart, ctx1);
         {$else}
           err := SC_SetIncProc(SC_IncLSBPart, ctx1);
         {$endif}
       end;
  end;

  CheckError;
  ofs := 0;
  ReStartTimer(HR);
  repeat
    for i:=1 to 99 do begin
      Err := SC_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
      ofs := ofs + BSIZE;
    end;
    {$ifdef USE_INT64}
      write(erroutput, 100.0*ofs/oma:1:3,'%'#13);
    {$else}
      write(100.0*ofs/oma:1:3,'%'#13);
    {$endif}
    Err := SC_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
    CheckError;
    i := random(BSIZE);
    Err := SC_CTR_Init(key, sizeof(key), CTR, ctx2);
    CheckError;
    case n of
      1: begin
           {$ifdef FPC_ProcVar}
             err := SC_SetIncProc(@SC_IncMSBFull, ctx2);
           {$else}
             err := SC_SetIncProc(SC_IncMSBFull, ctx2);
           {$endif}
         end;
      2: begin
           {$ifdef FPC_ProcVar}
             err := SC_SetIncProc(@SC_IncLSBFull, ctx2);
           {$else}
             err := SC_SetIncProc(SC_IncLSBFull, ctx2);
           {$endif}
         end;

      3: begin
           {$ifdef FPC_ProcVar}
             err := SC_SetIncProc(@SC_IncMSBPart, ctx2);
           {$else}
             err := SC_SetIncProc(SC_IncMSBPart, ctx2);
           {$endif}
         end;

      4: begin
           {$ifdef FPC_ProcVar}
             err := SC_SetIncProc(@SC_IncLSBPart, ctx2);
           {$else}
             err := SC_SetIncProc(SC_IncLSBPart, ctx2);
           {$endif}
         end;
      else begin
             writeln('Invalid n');
             halt;
           end;
    end;
    CheckError;
    {$ifdef USE_INT64}
      Err := SC_CTR_Seek64(CTR, ofs+i, ctx2);
    {$else}
      Err := SC_CTR_Seek(CTR, ofs+i, 0, ctx2);
    {$endif}
    CheckError;
    Err := SC_CTR_Encrypt(@pbuf[i], @cbuf2[i], 1, ctx2);
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
  writeln('Test program "Shacal-2 CTR Seek"    (C) 2010  W.Ehrhardt');
  {$ifdef USEDLL}
    writeln('DLL Version: ',SC_DLL_Version);
  {$endif}
  writeln;
  writeln('Test using standard SC_IncMSBFull');
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
