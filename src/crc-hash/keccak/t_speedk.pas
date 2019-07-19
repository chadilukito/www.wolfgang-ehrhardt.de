{-Test Cyc/B and MB/s for Keccak, needs HRTimer/TSC from Util archive}

program t_speedk;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}


{$ifndef FPC}
  {$B-,N+}
{$endif}


uses
  {$ifdef WIN32or64}
    {$ifdef UNIT_SCOPE}
      winapi.windows,
    {$else}
      windows,
    {$endif}
  {$endif}
  hrtimer,
  {$ifdef WINCRT}
    wincrt,
  {$else}
    crt,
  {$endif}
  keccak_n;

const
  NUMBYTES  = 50000;
  NUMROUNDS = 20;
  BYTECOUNT = NUMBYTES*NUMROUNDS;
  MEGCOUNT  = BYTECOUNT/1E6;
  DThresh   = 0.3;

{$ifndef BIT16}
  MinRnd = 10;
{$else}
  MinRnd = 5;
{$endif}

type
  TKeccakMaxDigest = packed array[0..63] of byte;  {Keccak-512 digest}

type
  TCompArray = array[0..MinRnd] of comp;
  TBuf  = array[1..NUMBYTES] of byte;
  TTest = record
            name : string[11];
            adiff: TCompArray;
            mdiff: double;
            CpB  : double;
            MBs  : double;
            D100 : double;
            done : boolean;
          end;

var
  T_KEC224  : TTest;
  T_KEC256  : TTest;
  T_KEC384  : TTest;
  T_KEC512  : TTest;
  MaxD100   : double;
  rnd       : integer;
  start     : comp;
  stop      : comp;
  HR        : THRTimer;
  pbuf      : ^TBuf;



{---------------------------------------------------------------------------}
procedure keccak_full(kbits: integer; data: pointer; bytelen: longint; var dig: TKeccakMaxDigest);
var
  state: thashState;
  i: integer;
begin
  i := Init(state,kbits);
  if i=0 then i := Update(state, data, bytelen*8);
  if i=0 then i := Final(state,@dig[0]);
  if i<>0 then begin
    writeln('Error ',i, ' for kbits=',kbits);
    halt;
  end;
end;


{---------------------------------------------------------------------------}
procedure CalcStat(var Test: TTest);
var
  sum,diff: comp;
  sec,mean,delta,t: double;
  i,n: integer;
begin

  if rnd=0 then Test.done := false;
  if Test.done then exit;

  diff:= stop-start;
  sec := diff/CPUFrequency;
  i := rnd mod (MinRnd+1);
  Test.adiff[i] := diff;
  if rnd>MinRnd then n:=MinRnd else n:=rnd;

  sum := 0;
  for i:=0 to n do sum := sum + Test.adiff[i];
  mean := sum/(n+1);

  if rnd>0 then begin
    delta := abs(mean-Test.adiff[0]);
    for i:=1 to n do begin
      t := abs(mean-Test.adiff[0]);
      if t>delta then delta := t;
    end;
  end
  else begin
    delta := diff;
  end;
  Test.CpB  := diff/BYTECOUNT;
  Test.MBs  := MEGCOUNT/sec;
  Test.D100 := 100*delta/diff;
  Test.done := (rnd>MinRnd) and (Test.D100<DThresh);
  if Test.D100>MaxD100 then MaxD100 := Test.D100;
end;


{---------------------------------------------------------------------------}
procedure ShowResult(var Test: TTest);
begin
  CalcStat(Test);
  writeln(' ',Test.name,'':10-length(Test.name), Test.CpB:8:1, Test.MBs:8:2, Test.D100:8:1);
end;


{---------------------------------------------------------------------------}
procedure SHA224_Test;
var
  bc: TKeccakMaxDigest;
  rounds: integer;
begin
  if (rnd<=MinRnd) or not T_KEC224.done then begin
    start := ReadCycles(HR);
    for rounds:=1 to NUMROUNDS do keccak_full(224, pbuf, sizeof(TBuf), bc);
    stop := ReadCycles(HR);
  end;
  ShowResult(T_KEC224);
end;


{---------------------------------------------------------------------------}
procedure SHA256_Test;
var
  bc: TKeccakMaxDigest;
  rounds: integer;
begin
  if (rnd<=MinRnd) or not T_KEC256.done then begin
    start := ReadCycles(HR);
    for rounds:=1 to NUMROUNDS do keccak_full(256, pbuf, sizeof(TBuf), bc);
    stop := ReadCycles(HR);
  end;
  ShowResult(T_KEC256);
end;


{---------------------------------------------------------------------------}
procedure SHA384_Test;
var
  bc: TKeccakMaxDigest;
  rounds: integer;
begin
  if (rnd<=MinRnd) or not T_KEC384.done then begin
    start := ReadCycles(HR);
    for rounds:=1 to NUMROUNDS do keccak_full(384, pbuf, sizeof(TBuf), bc);
    stop := ReadCycles(HR);
  end;
  ShowResult(T_KEC384);
end;


{---------------------------------------------------------------------------}
procedure SHA512_Test;
var
  bc: TKeccakMaxDigest;
  rounds: integer;
begin
  if (rnd<=MinRnd) or not T_KEC512.done then begin
    start := ReadCycles(HR);
    for rounds:=1 to NUMROUNDS do keccak_full(512, pbuf, sizeof(TBuf), bc);
    stop := ReadCycles(HR);
  end;
  ShowResult(T_KEC512);
end;

var
  i: word;
  done: boolean;
begin

  {$ifdef BASM16}
    {$ifdef DumpAlign}
      if readkey=#27 then halt;
    {$endif}
  {$endif}

  {$ifdef VER90 }
    InitCRT;  {D2}
  {$endif}
  {$ifdef WIN32or64}
    if Paramcount=0 then SetPriorityClass(GetCurrentProcess,HIGH_PRIORITY_CLASS);
  {$endif}

  randseed := 1234567;
  new(pbuf);
  for i:=1 to NUMBYTES do pbuf^[i] := random(256);

  T_KEC224.name  := 'Keccak224';
  T_KEC256.name  := 'Keccak256';
  T_KEC384.name  := 'Keccak384';
  T_KEC512.name  := 'Keccak512';

  clrscr;
  {$ifdef WINCRT}
    writeln('Name      ':11, 'Cyc/B':8, 'MB/s':8, 'D[%]':8, CPUFrequency/1E6:10:1);
  {$else}
    textcolor(lightgreen);
    writeln('Name      ':11, 'Cyc/B':8, 'MB/s':8, 'D[%]':8, CPUFrequency/1E6:10:1);
    textcolor(lightgray);
  {$endif}
  done := false;
  rnd  := 0;
  repeat
    StartTimer(HR);
    gotoxy(1,2);
    MaxD100 := 0.0;
    SHA224_Test;
    SHA256_Test;
    SHA384_Test;
    SHA512_Test;
    inc(rnd);
    writeln('Rounds: ',rnd);
    {Some compilers have no break!!}
    if keypressed and (readkey=#27) then done := true;
    if (rnd>MinRnd) and (MaxD100 < DThresh)  then done := true;
 until done;
end.
