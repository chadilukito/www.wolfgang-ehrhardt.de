{-Test prog for Blowfish CTR Seek, (c) we July 2010}

program T_BF_CSK;

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
      BF_Intv;
    {$else}
      BF_Intf;
    {$endif}
  {$else}
    BF_base, BF_ctr;
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
  ctx1, ctx2: TBFContext;
  Err : integer;

{$ifdef USE_INT64}
const
  BSIZE=$8000;
{$else}
const
  BSIZE=8192;
{$endif}



{---------------------------------------------------------------------------}
procedure My_IncMSBFull(var CTR: TBFBlock);
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
  key128 : array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                                   $ab,$f7,$15,$88,$09,$cf,$4f,$3c);

     CTR : TBFBlock             = ($f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

  plain  : array[0..63] of char8= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  ct_ctr : array[0..63] of byte = ($81,$07,$98,$2d,$92,$73,$12,$40,
                                   $ba,$58,$c1,$c9,$32,$f7,$ea,$67,
                                   $f3,$a9,$8f,$eb,$25,$51,$fa,$c2,
                                   $5c,$17,$80,$be,$6b,$a0,$39,$e5,
                                   $dc,$1f,$eb,$c3,$81,$53,$af,$20,
                                   $bd,$15,$6d,$4b,$89,$65,$8a,$d5,
                                   $6c,$a1,$dc,$0e,$a0,$07,$5b,$c3,
                                   $8e,$3c,$b4,$6d,$9e,$af,$a1,$64);


var
  ct: array[0..255] of byte;
  SO: integer;
begin

  writeln('Known vector test, 128 bit key');
  Err := BF_CTR_Init(key128, sizeof(key128), CTR, ctx2);
  CheckError;
  if userdef then begin
    Err := BF_SetIncProc({$ifdef FPC_ProcVar}@{$endif}My_IncMSBFull, ctx2);
    CheckError;
  end;
  for SO:=0 to 63 do begin
    write('.');
    Err := BF_CTR_Seek(CTR, SO, 0, ctx2);
    CheckError;
    Err := BF_CTR_Encrypt(@plain[SO], @ct[SO], 1, ctx2);
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
     CTR : TBFBlock             = ($f8,$f9,$fa,$fb,$fc,$fd,$fe,$ff);

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
  Err := BF_CTR_Init(key128, sizeof(key128), CTR, ctx1);
  CheckError;
  case n of
    1: begin
         writeln('IncProc = BF_IncMSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = BF_IncMSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := BF_SetIncProc(@BF_IncMSBFull, ctx1);
         {$else}
           err := BF_SetIncProc(BF_IncMSBFull, ctx1);
         {$endif}
       end;
    2: begin
         writeln('IncProc = BF_IncLSBFull,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = BF_IncLSBFull,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := BF_SetIncProc(@BF_IncLSBFull, ctx1);
         {$else}
           err := BF_SetIncProc(BF_IncLSBFull, ctx1);
         {$endif}
       end;

    3: begin
         writeln('IncProc = BF_IncMSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = BF_IncMSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := BF_SetIncProc(@BF_IncMSBPart, ctx1);
         {$else}
           err := BF_SetIncProc(BF_IncMSBPart, ctx1);
         {$endif}
       end;

    4: begin
         writeln('IncProc = BF_IncLSBPart,   max. offset = ',oma);
         {$ifdef USE_INT64}
           writeln(erroutput, 'IncProc = BF_IncLSBPart,   max. offset = ',oma);
         {$endif}
         {$ifdef FPC_ProcVar}
           err := BF_SetIncProc(@BF_IncLSBPart, ctx1);
         {$else}
           err := BF_SetIncProc(BF_IncLSBPart, ctx1);
         {$endif}
       end;
  end;

  CheckError;
  ofs := 0;
  ReStartTimer(HR);
  repeat
    for i:=1 to 99 do begin
      Err := BF_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
      ofs := ofs + BSIZE;
    end;
    {$ifdef USE_INT64}
      write(erroutput, 100.0*ofs/oma:1:3,'%'#13);
    {$else}
      write(100.0*ofs/oma:1:3,'%'#13);
    {$endif}
    Err := BF_CTR_Encrypt(@pbuf, @cbuf1, BSIZE, ctx1);
    CheckError;
    i := random(BSIZE);
    Err := BF_CTR_Init(key128, sizeof(key128), CTR, ctx2);
    CheckError;
    case n of
      1: begin
           {$ifdef FPC_ProcVar}
             err := BF_SetIncProc(@BF_IncMSBFull, ctx2);
           {$else}
             err := BF_SetIncProc(BF_IncMSBFull, ctx2);
           {$endif}
         end;
      2: begin
           {$ifdef FPC_ProcVar}
             err := BF_SetIncProc(@BF_IncLSBFull, ctx2);
           {$else}
             err := BF_SetIncProc(BF_IncLSBFull, ctx2);
           {$endif}
         end;

      3: begin
           {$ifdef FPC_ProcVar}
             err := BF_SetIncProc(@BF_IncMSBPart, ctx2);
           {$else}
             err := BF_SetIncProc(BF_IncMSBPart, ctx2);
           {$endif}
         end;

      4: begin
           {$ifdef FPC_ProcVar}
             err := BF_SetIncProc(@BF_IncLSBPart, ctx2);
           {$else}
             err := BF_SetIncProc(BF_IncLSBPart, ctx2);
           {$endif}
         end;
      else begin
             writeln('Invalid n');
             halt;
           end;
    end;
    CheckError;
    {$ifdef USE_INT64}
      Err := BF_CTR_Seek64(CTR, ofs+i, ctx2);
    {$else}
      Err := BF_CTR_Seek(CTR, ofs+i, 0, ctx2);
    {$endif}
    CheckError;
    Err := BF_CTR_Encrypt(@pbuf[i], @cbuf2[i], 1, ctx2);
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
  writeln('Test program "BF CTR Seek"    (C) 2010  W.Ehrhardt');
  {$ifdef USEDLL}
    writeln('DLL Version: ',BF_DLL_Version);
  {$endif}
  writeln;
  writeln('Test using standard BF_IncMSBFull');
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
