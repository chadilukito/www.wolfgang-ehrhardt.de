{Sosemanuk include file for 16 bit code pre TP6 , W.Ehrhardt Apr.2009}

{sose_keysetup and sose_ivsetup reuse code from my Serpent implementation.}
{MakeStreamBlock is based on sosemanukfast.java from the eSTREAM submission.}


{---------------------------------------------------------------------------}
function RotL(X: longint; c: word): longint;
  {-Rotate left}
inline(
  $59/           {  pop    cx    }
  $58/           {  pop    ax    }
  $5A/           {  pop    dx    }

  $83/$F9/$10/   {  cmp    cx,16 }
  $72/$06/       {  jb     S     }
  $92/           {  xchg   dx,ax }
  $83/$E9/$10/   {  sub    cx,16 }
  $74/$09/       {  je     X     }

  $2B/$DB/       {S:sub    bx,bx }
  $D1/$D0/       {L:rcl    ax,1  }
  $D1/$D2/       {  rcl    dx,1  }
  $13/$C3/       {  adc    ax,bx }
  $49/           {  dec    cx    }
  $75/$F7);      {  jne    L     }
                 {X:             }

{---------------------------------------------------------------------------}
function RotR(X: longint; c: word): longint;
  {-Rotate left}
inline(
  $59/           {  pop    cx   }
  $58/           {  pop    ax   }
  $5A/           {  pop    dx   }

  $83/$F9/$10/   {  cmp    cx,16}
  $72/$06/       {  jb     S    }
  $92/           {  xchg   dx,ax}
  $83/$E9/$10/   {  sub    cx,16}
  $74/$09/       {  je     X    }

  $8B/$DA/       {  mov   bx,dx }
  $D1/$EB/       {L:shr   bx,1  }
  $D1/$D8/       {  rcr   ax,1  }
  $D1/$DA/       {  rcr   dx,1  }
  $49/           {  dec   cx    }
  $75/$F7);      {  jne   L     }
                 {X:            }


{---------------------------------------------------------------------------}
function SHL8(X: longint): longint;
  {-Shift left 8 bit}
inline(
  $58/           {  pop    ax    }
  $5A/           {  pop    dx    }
  $8A/$F2/       {  mov    dh,dl }
  $8A/$D4/       {  mov    dl,ah }
  $8A/$E0/       {  mov    ah,al }
  $2A/$C0);      {  sub    al,al }

{---------------------------------------------------------------------------}
function SHR8(X: longint): longint;
  {-Shift right 8 bit}
inline(
  $58/           {  pop    ax    }
  $5A/           {  pop    dx    }
  $8A/$C4/       {  mov    al,ah }
  $8A/$E2/       {  mov    ah,dl }
  $8A/$D6/       {  mov    dl,dh }
  $2A/$F6);      {  sub    dh,dh }


{---------------------------------------------------------------------------}
procedure RND0(var x0,x1,x2,x3: longint);
var
  t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15,t16,t17,t18: longint;
begin
  t01 := x1  xor x2;
  t02 := x0  or  x3;
  t03 := x0  xor x1;
  t04 := t02 xor t01;
  t05 := x2  or  t04;
  t06 := x0  xor x3;
  t07 := x1  or  x2;
  t08 := x3  and t05;
  t09 := t03 and t07;
  t10 := t09 xor t08;
  t11 := t09 and t10;
  t12 := x2  xor x3;
  t13 := t07 xor t11;
  t14 := x1  and t06;
  t15 := t06 xor t13;
  t16 :=     not t15;
  t17 := t16 xor t14;
  t18 := t12 xor t17;
  x0  := t16;
  x1  := t18;
  x2  := t10;
  x3  := t04;
end;


{---------------------------------------------------------------------------}
procedure RND1(var x0,x1,x2,x3: longint);
var
  t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15,t16,t17,t18: longint;
begin
  t01 := x0  or  x3;
  t02 := x2  xor x3;
  t03 :=     not x1;
  t04 := x0  xor x2;
  t05 := x0  or  t03;
  t06 := x3  and t04;
  t07 := t01 and t02;
  t08 := x1  or  t06;
  t09 := t02 xor t05;
  t10 := t07 xor t08;
  t11 := t01 xor t10;
  t12 := t09 xor t11;
  t13 := x1  and x3;
  t14 :=     not t10;
  t15 := t13 xor t12;
  t16 := t10 or  t15;
  t17 := t05 and t16;
  t18 := x2  xor t17;
  x0  := t18;
  x1  := t15;
  x2  := t09;
  x3  := t14;
end;


{---------------------------------------------------------------------------}
procedure RND2(var x0,x1,x2,x3: longint); 
var
  t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15,t16: longint;
begin
  t01 := x0  or  x2;
  t02 := x0  xor x1;
  t03 := x3  xor t01;
  t04 := t02 xor t03;
  t05 := x2  xor t04;
  t06 := x1  xor t05;
  t07 := x1  or  t05;
  t08 := t01 and t06;
  t09 := t03 xor t07;
  t10 := t02 or  t09;
  t11 := t10 xor t08;
  t12 := x0  or  x3;
  t13 := t09 xor t11;
  t14 := x1  xor t13;
  t15 :=     not t09;
  t16 := t12 xor t14;
  x0  := t04;
  x1  := t11;
  x2  := t16;
  x3  := t15;
end;


{---------------------------------------------------------------------------}
procedure RND3(var x0,x1,x2,x3: longint);
var
  t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15,t16,t17,t18: longint;
begin
  t01 := x0  xor x2;
  t02 := x0  or  x3;
  t03 := x0  and x3;
  t04 := t01 and t02;
  t05 := x1  or  t03;
  t06 := x0  and x1;
  t07 := x3  xor t04;
  t08 := x2  or  t06;
  t09 := x1  xor t07;
  t10 := x3  and t05;
  t11 := t02 xor t10;
  t12 := t08 xor t09;
  t13 := x3  or  t12;
  t14 := x0  or  t07;
  t15 := x1  and t13;
  t16 := t08 xor t11;
  t17 := t14 xor t15;
  t18 := t05 xor t04;
  x0  := t17;
  x1  := t18;
  x2  := t16;
  x3  := t12;
end;


{---------------------------------------------------------------------------}
procedure RND4(var x0,x1,x2,x3: longint); 
var
  t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15,t16,t17,t18: longint;
begin
  t01 := x0  or  x1;
  t02 := x1  or  x2;
  t03 := x0  xor t02;
  t04 := x1  xor x3;
  t05 := x3  or  t03;
  t06 := x3  and t01;
  t07 := t03 xor t06;
  t08 := t07 and t04;
  t09 := t04 and t05;
  t10 := x2  xor t06;
  t11 := x1  and x2;
  t12 := t04 xor t08;
  t13 := t11 or  t03;
  t14 := t10 xor t09;
  t15 := x0  and t05;
  t16 := t11 or  t12;
  t17 := t13 xor t08;
  t18 := t15 xor t16;
  x0  := not t14;
  x1  := t18;
  x2  := t17;
  x3  := t07;
end;


{---------------------------------------------------------------------------}
procedure RND5(var x0,x1,x2,x3: longint); 
var
  t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15,t16,t17: longint;
begin
  t01 := x1  xor x3;
  t02 := x1  or  x3;
  t03 := x0  and t01;
  t04 := x2  xor t02;
  t05 := t03 xor t04;
  t06 :=     not t05;
  t07 := x0  xor t01;
  t08 := x3  or  t06;
  t09 := x1  or  t05;
  t10 := x3  xor t08;
  t11 := x1  or  t07;
  t12 := t03 or  t06;
  t13 := t07 or  t10;
  t14 := t01 xor t11;
  t15 := t09 xor t13;
  t16 := t07 xor t08;
  t17 := t12 xor t14;
  x0  := t06;
  x1  := t16;
  x2  := t15;
  x3  := t17;
end;


{---------------------------------------------------------------------------}
procedure RND6(var x0,x1,x2,x3: longint); 
var
  t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15,t16,t17,t18,t19: longint;
begin
  t01 := x0  and x3;
  t02 := x1  xor x2;
  t03 := x0  xor x3;
  t04 := t01 xor t02;
  t05 := x1  or  x2;
  t06 :=     not t04;
  t07 := t03 and t05;
  t08 := x1  and t06;
  t09 := x0  or  x2;
  t10 := t07 xor t08;
  t11 := x1  or  x3;
  t12 := x2  xor t11;
  t13 := t09 xor t10;
  t14 :=     not t13;
  t15 := t06 and t03;
  t16 := t12 xor t07;
  t17 := x0  xor x1;
  t18 := t14 xor t15;
  t19 := t17 xor t18;
  x0  := t19;
  x1  := t06;
  x2  := t14;
  x3  := t16;
end;


{---------------------------------------------------------------------------}
procedure RND7(var x0,x1,x2,x3: longint); 
var
  t01,t02,t03,t04,t05,t06,t07,t08,t09,t10,t11,t12,t13,t14,t15,t16,t17,t18,t19: longint;
begin
  t01 := x0  and x2;
  t02 :=     not x3;
  t03 := x0  and t02;
  t04 := x1  or  t01;
  t05 := x0  and x1;
  t06 := x2  xor t04;
  t07 := t03 xor t06;
  t08 := x2  or  t07;
  t09 := x3  or  t05;
  t10 := x0  xor t08;
  t11 := t04 and t07;
  t12 := t09 xor t10;
  t13 := x1  xor t12;
  t14 := t01 xor t12;
  t15 := x2  xor t05;
  t16 := t11 or  t13;
  t17 := t02 or  t14;
  t18 := t15 xor t17;
  t19 := x0  xor t16;
  x0  := t18;
  x1  := t12;
  x2  := t19;
  x3  := t07;
end;


{---------------------------------------------------------------------------}
procedure Transform(var x0,x1,x2,x3: longint);
begin
  x0 := RotL(x0, 13);
  x2 := RotL(x2,  3);
  x1 := x1 xor x0 xor x2;
  x3 := x3 xor x2 xor (x0 shl 3);
  x1 := RotL(x1, 1);
  x3 := RotL(x3, 7);
  x0 := x0 xor x1 xor x3;
  x2 := x2 xor x3 xor (x1 shl 7);
  x0 := RotL(x0,  5);
  x2 := RotL(x2, 22);
end;



{---------------------------------------------------------------------------}
function sose_keysetup(var ctx: sose_ctx; key: pointer; keybits: word): integer;
  {-Sosemanuk key setup}
var
  i: integer;
  klen: word;
  t: longint;
  lkey: array[0..35] of byte;
  K0: array[0..7] of longint absolute lkey;
const
  phi = longint($9E3779B9);
begin
  {$ifdef CHECK_KEY_BITS}
    if KeyBits<128 then begin
      sose_keysetup := -1;
      exit;
    end;
  {$endif}

  sose_keysetup := 0;
  klen := KeyBits div 8;

  {Use at most 256 bits}
  if klen>31 then move(key^,lkey,32)
  else begin
    fillchar(lkey, 32,0);
    move(key^,lkey,klen);
    lkey[klen] := 1;
  end;

  with ctx do begin
    t := K0[7];
    for i:=0 to 7 do begin
      t := RotL(K0[i] xor K0[(i+3) and 7] xor K0[(i+5) and 7] xor t xor phi xor longint(i), 11);
      K0[i] := t;
      RndKey[i] := t;
    end;
    for i:=8 to 99 do begin
      t := RotL(RndKey[i-8] xor RndKey[i-5] xor RndKey[i-3] xor t xor phi xor longint(i), 11);
      RndKey[i] := t;
    end;
    i := 0;
    while i<96 do begin
      RND3(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);
      RND2(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);
      RND1(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);
      RND0(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);
      RND7(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);
      RND6(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);
      RND5(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);
      RND4(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);
    end;
    RND3(RndKey[96], RndKey[97], RndKey[98], RndKey[99]);
  end;
end;



{---------------------------------------------------------------------------}
procedure sose_ivsetup(var ctx: sose_ctx; IV: pointer);
  {-IV setup, 128 bits of IV^ are used. It is the user's responsibility to }
  { supply least 128 accessible IV bits. After having called sose_keysetup,}
  { the user is allowed to call sose_ivsetup different times in order to   }
  { encrypt/decrypt different messages with the same key but different IV's}
var
  x0,x1,x2,x3: longint;
begin
  x0 := PWA4(IV)^[0];
  x1 := PWA4(IV)^[1];
  x2 := PWA4(IV)^[2];
  x3 := PWA4(IV)^[3];

  with ctx do begin
    x0 := x0 xor RndKey[0];
    x1 := x1 xor RndKey[1];
    x2 := x2 xor RndKey[2];
    x3 := x3 xor RndKey[3];
    RND0(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[4];
    x1 := x1 xor RndKey[5];
    x2 := x2 xor RndKey[6];
    x3 := x3 xor RndKey[7];
    RND1(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[8];
    x1 := x1 xor RndKey[9];
    x2 := x2 xor RndKey[10];
    x3 := x3 xor RndKey[11];
    RND2(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[12];
    x1 := x1 xor RndKey[13];
    x2 := x2 xor RndKey[14];
    x3 := x3 xor RndKey[15];
    RND3(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[16];
    x1 := x1 xor RndKey[17];
    x2 := x2 xor RndKey[18];
    x3 := x3 xor RndKey[19];
    RND4(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[20];
    x1 := x1 xor RndKey[21];
    x2 := x2 xor RndKey[22];
    x3 := x3 xor RndKey[23];
    RND5(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[24];
    x1 := x1 xor RndKey[25];
    x2 := x2 xor RndKey[26];
    x3 := x3 xor RndKey[27];
    RND6(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[28];
    x1 := x1 xor RndKey[29];
    x2 := x2 xor RndKey[30];
    x3 := x3 xor RndKey[31];
    RND7(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[32];
    x1 := x1 xor RndKey[33];
    x2 := x2 xor RndKey[34];
    x3 := x3 xor RndKey[35];
    RND0(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[36];
    x1 := x1 xor RndKey[37];
    x2 := x2 xor RndKey[38];
    x3 := x3 xor RndKey[39];
    RND1(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[40];
    x1 := x1 xor RndKey[41];
    x2 := x2 xor RndKey[42];
    x3 := x3 xor RndKey[43];
    RND2(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[44];
    x1 := x1 xor RndKey[45];
    x2 := x2 xor RndKey[46];
    x3 := x3 xor RndKey[47];
    RND3(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    lfsr[9] := x0;
    lfsr[8] := x1;
    lfsr[7] := x2;
    lfsr[6] := x3;

    x0 := x0 xor RndKey[48];
    x1 := x1 xor RndKey[49];
    x2 := x2 xor RndKey[50];
    x3 := x3 xor RndKey[51];
    RND4(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[52];
    x1 := x1 xor RndKey[53];
    x2 := x2 xor RndKey[54];
    x3 := x3 xor RndKey[55];
    RND5(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[56];
    x1 := x1 xor RndKey[57];
    x2 := x2 xor RndKey[58];
    x3 := x3 xor RndKey[59];
    RND6(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[60];
    x1 := x1 xor RndKey[61];
    x2 := x2 xor RndKey[62];
    x3 := x3 xor RndKey[63];
    RND7(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);
    {xxx}
    x0 := x0 xor RndKey[64];
    x1 := x1 xor RndKey[65];
    x2 := x2 xor RndKey[66];
    x3 := x3 xor RndKey[67];
    RND0(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[68];
    x1 := x1 xor RndKey[69];
    x2 := x2 xor RndKey[70];
    x3 := x3 xor RndKey[71];
    RND1(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    fsmr[1] := x0;
    lfsr[4] := x1;
    fsmr[2] := x2;
    lfsr[5] := x3;

    x0 := x0 xor RndKey[72];
    x1 := x1 xor RndKey[73];
    x2 := x2 xor RndKey[74];
    x3 := x3 xor RndKey[75];
    RND2(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[76];
    x1 := x1 xor RndKey[77];
    x2 := x2 xor RndKey[78];
    x3 := x3 xor RndKey[79];
    RND3(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[80];
    x1 := x1 xor RndKey[81];
    x2 := x2 xor RndKey[82];
    x3 := x3 xor RndKey[83];
    RND4(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[84];
    x1 := x1 xor RndKey[85];
    x2 := x2 xor RndKey[86];
    x3 := x3 xor RndKey[87];
    RND5(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[88];
    x1 := x1 xor RndKey[89];
    x2 := x2 xor RndKey[90];
    x3 := x3 xor RndKey[91];
    RND6(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    x0 := x0 xor RndKey[92];
    x1 := x1 xor RndKey[93];
    x2 := x2 xor RndKey[94];
    x3 := x3 xor RndKey[95];
    RND7(x0,x1,x2,x3);
    Transform(x0,x1,x2,x3);

    lfsr[3] := x0 xor RndKey[96];
    lfsr[2] := x1 xor RndKey[97];
    lfsr[1] := x2 xor RndKey[98];
    lfsr[0] := x3 xor RndKey[99];
  end;
end;


{$ifdef Q_OPT}
{$Q-}
{$endif}

{$R-}

{---------------------------------------------------------------------------}
procedure MakeStreamBlock(var ctx: sose_ctx; pblk: TPSMBlockW; nblk: word);
  {-Generate next nblk key stream blocks}
var
  s0,s1,s2,s3,s4,
  s5,s6,s7,s8,s9,
  r1,r2,
  f0,f1,f2,f3,f4: longint;
  v0,v1,v2,v3,tt: longint;
type
  TBA4 = packed array[0..3] of byte;
begin
  with ctx do begin
    s0 := lfsr[0];
    s1 := lfsr[1];
    s2 := lfsr[2];
    s3 := lfsr[3];
    s4 := lfsr[4];
    s5 := lfsr[5];
    s6 := lfsr[6];
    s7 := lfsr[7];
    s8 := lfsr[8];
    s9 := lfsr[9];
    r1 := fsmr[1];
    r2 := fsmr[2];
    while nblk>0 do begin
      tt := r1;
      r1 := r2 + (s1 xor (sig[r1 and 1] and s8));
      r2 := RotL(tt * $54655307,7);
      v0 := s0;
      s0 := (SHL8(s0) xor mulAlpha[TBA4(s0)[3]]) xor (SHR8(s3) xor divAlpha[byte(s3)]) xor s9;
      f0 := (s9 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s2 xor (sig[r1 and 1] and s9));
      r2 := RotL(tt * $54655307,7);
      v1 := s1;
      s1 := (SHL8(s1) xor mulAlpha[TBA4(s1)[3]]) xor (SHR8(s4) xor divAlpha[byte(s4)]) xor s0;
      f1 := (s0 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s3 xor (sig[r1 and 1] and s0));
      r2 := RotL(tt * $54655307,7);
      v2 := s2;
      s2 := (SHL8(s2) xor mulAlpha[TBA4(s2)[3]]) xor (SHR8(s5) xor divAlpha[byte(s5)]) xor s1;
      f2 := (s1 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s4 xor (sig[r1 and 1] and s1));
      r2 := RotL(tt * $54655307,7);
      v3 := s3;
      s3 := (SHL8(s3) xor mulAlpha[TBA4(s3)[3]]) xor (SHR8(s6) xor divAlpha[byte(s6)]) xor s2;
      f3 := (s2 + r1) xor r2;

      f4 := f0;
      f0 := f0 and f2;
      f0 := f0 xor f3;
      f2 := f2 xor f1;
      f2 := f2 xor f0;
      f3 := f3  or f4;
      f3 := f3 xor f1;
      f4 := f4 xor f2;
      f1 := f3;
      f3 := f3  or f4;
      f3 := f3 xor f0;
      f0 := f0 and f1;
      f4 := f4 xor f0;
      f1 := f1 xor f3;
      f1 := f1 xor f4;
      f4 := not f4;

      pblk^[0] := f2 xor v0;
      pblk^[1] := f3 xor v1;
      pblk^[2] := f1 xor v2;
      pblk^[3] := f4 xor v3;

      tt := r1;
      r1 := r2 + (s5 xor (sig[r1 and 1] and s2));
      r2 := RotL(tt * $54655307,7);
      v0 := s4;
      s4 := (SHL8(s4) xor mulAlpha[TBA4(s4)[3]]) xor (SHR8(s7) xor divAlpha[byte(s7)]) xor s3;
      f0 := (s3 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s6 xor (sig[r1 and 1] and s3));
      r2 := RotL(tt * $54655307,7);
      v1 := s5;
      s5 := (SHL8(s5) xor mulAlpha[TBA4(s5)[3]]) xor (SHR8(s8) xor divAlpha[byte(s8)]) xor s4;
      f1 := (s4 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s7 xor (sig[r1 and 1] and s4));
      r2 := RotL(tt * $54655307,7);
      v2 := s6;
      s6 := (SHL8(s6) xor mulAlpha[TBA4(s6)[3]]) xor (SHR8(s9) xor divAlpha[byte(s9)]) xor s5;
      f2 := (s5 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s8 xor (sig[r1 and 1] and s5));
      r2 := RotL(tt * $54655307,7);
      v3 := s7;
      s7 := (SHL8(s7) xor mulAlpha[TBA4(s7)[3]]) xor (SHR8(s0) xor divAlpha[byte(s0)]) xor s6;
      f3 := (s6 + r1) xor r2;

      f4 := f0;
      f0 := f0 and f2;
      f0 := f0 xor f3;
      f2 := f2 xor f1;
      f2 := f2 xor f0;
      f3 := f3  or f4;
      f3 := f3 xor f1;
      f4 := f4 xor f2;
      f1 := f3;
      f3 := f3  or f4;
      f3 := f3 xor f0;
      f0 := f0 and f1;
      f4 := f4 xor f0;
      f1 := f1 xor f3;
      f1 := f1 xor f4;
      f4 := not f4;

      pblk^[4] := f2 xor v0;
      pblk^[5] := f3 xor v1;
      pblk^[6] := f1 xor v2;
      pblk^[7] := f4 xor v3;

      tt := r1;
      r1 := r2 + (s9 xor (sig[r1 and 1] and s6));
      r2 := RotL(tt * $54655307,7);
      v0 := s8;
      s8 := (SHL8(s8) xor mulAlpha[TBA4(s8)[3]]) xor (SHR8(s1) xor divAlpha[byte(s1)]) xor s7;
      f0 := (s7 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s0 xor (sig[r1 and 1] and s7));
      r2 := RotL(tt * $54655307,7);
      v1 := s9;
      s9 := (SHL8(s9) xor mulAlpha[TBA4(s9)[3]]) xor (SHR8(s2) xor divAlpha[byte(s2)]) xor s8;
      f1 := (s8 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s1 xor (sig[r1 and 1] and s8));
      r2 := RotL(tt * $54655307,7);
      v2 := s0;
      s0 := (SHL8(s0) xor mulAlpha[TBA4(s0)[3]]) xor (SHR8(s3) xor divAlpha[byte(s3)]) xor s9;
      f2 := (s9 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s2 xor (sig[r1 and 1] and s9));
      r2 := RotL(tt * $54655307,7);
      v3 := s1;
      s1 := (SHL8(s1) xor mulAlpha[TBA4(s1)[3]]) xor (SHR8(s4) xor divAlpha[byte(s4)]) xor s0;
      f3 := (s0 + r1) xor r2;

      f4 := f0;
      f0 := f0 and f2;
      f0 := f0 xor f3;
      f2 := f2 xor f1;
      f2 := f2 xor f0;
      f3 := f3  or f4;
      f3 := f3 xor f1;
      f4 := f4 xor f2;
      f1 := f3;
      f3 := f3  or f4;
      f3 := f3 xor f0;
      f0 := f0 and f1;
      f4 := f4 xor f0;
      f1 := f1 xor f3;
      f1 := f1 xor f4;
      f4 := not f4;

      pblk^[ 8] := f2 xor v0;
      pblk^[ 9] := f3 xor v1;
      pblk^[10] := f1 xor v2;
      pblk^[11] := f4 xor v3;

      tt := r1;
      r1 := r2 + (s3 xor (sig[r1 and 1] and s0));
      r2 := RotL(tt * $54655307,7);
      v0 := s2;
      s2 := (SHL8(s2) xor mulAlpha[TBA4(s2)[3]]) xor (SHR8(s5) xor divAlpha[byte(s5)]) xor s1;
      f0 := (s1 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s4 xor (sig[r1 and 1] and s1));
      r2 := RotL(tt * $54655307,7);
      v1 := s3;
      s3 := (SHL8(s3) xor mulAlpha[TBA4(s3)[3]]) xor (SHR8(s6) xor divAlpha[byte(s6)]) xor s2;
      f1 := (s2 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s5 xor (sig[r1 and 1] and s2));
      r2 := RotL(tt * $54655307,7);
      v2 := s4;
      s4 := (SHL8(s4) xor mulAlpha[TBA4(s4)[3]]) xor (SHR8(s7) xor divAlpha[byte(s7)]) xor s3;
      f2 := (s3 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s6 xor (sig[r1 and 1] and s3));
      r2 := RotL(tt * $54655307,7);
      v3 := s5;
      s5 := (SHL8(s5) xor mulAlpha[TBA4(s5)[3]]) xor (SHR8(s8) xor divAlpha[byte(s8)]) xor s4;
      f3 := (s4 + r1) xor r2;

      f4 := f0;
      f0 := f0 and f2;
      f0 := f0 xor f3;
      f2 := f2 xor f1;
      f2 := f2 xor f0;
      f3 := f3  or f4;
      f3 := f3 xor f1;
      f4 := f4 xor f2;
      f1 := f3;
      f3 := f3  or f4;
      f3 := f3 xor f0;
      f0 := f0 and f1;
      f4 := f4 xor f0;
      f1 := f1 xor f3;
      f1 := f1 xor f4;
      f4 := not f4;

      pblk^[12] := f2 xor v0;
      pblk^[13] := f3 xor v1;
      pblk^[14] := f1 xor v2;
      pblk^[15] := f4 xor v3;

      tt := r1;
      r1 := r2 + (s7 xor (sig[r1 and 1] and s4));
      r2 := RotL(tt * $54655307,7);
      v0 := s6;
      s6 := (SHL8(s6) xor mulAlpha[TBA4(s6)[3]]) xor (SHR8(s9) xor divAlpha[byte(s9)]) xor s5;
      f0 := (s5 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s8 xor (sig[r1 and 1] and s5));
      r2 := RotL(tt * $54655307,7);
      v1 := s7;
      s7 := (SHL8(s7) xor mulAlpha[TBA4(s7)[3]]) xor (SHR8(s0) xor divAlpha[byte(s0)]) xor s6;
      f1 := (s6 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s9 xor (sig[r1 and 1] and s6));
      r2 := RotL(tt * $54655307,7);
      v2 := s8;
      s8 := (SHL8(s8) xor mulAlpha[TBA4(s8)[3]]) xor (SHR8(s1) xor divAlpha[byte(s1)]) xor s7;
      f2 := (s7 + r1) xor r2;

      tt := r1;
      r1 := r2 + (s0 xor (sig[r1 and 1] and s7));
      r2 := RotL(tt * $54655307,7);
      v3 := s9;
      s9 := (SHL8(s9) xor mulAlpha[TBA4(s9)[3]]) xor (SHR8(s2) xor divAlpha[byte(s2)]) xor s8;
      f3 := (s8 + r1) xor r2;

      f4 := f0;
      f0 := f0 and f2;
      f0 := f0 xor f3;
      f2 := f2 xor f1;
      f2 := f2 xor f0;
      f3 := f3  or f4;
      f3 := f3 xor f1;
      f4 := f4 xor f2;
      f1 := f3;
      f3 := f3  or f4;
      f3 := f3 xor f0;
      f0 := f0 and f1;
      f4 := f4 xor f0;
      f1 := f1 xor f3;
      f1 := f1 xor f4;
      f4 := not f4;

      pblk^[16] := f2 xor v0;
      pblk^[17] := f3 xor v1;
      pblk^[18] := f1 xor v2;
      pblk^[19] := f4 xor v3;

      dec(nblk);
      inc(Ptr2Inc(pblk),sizeof(TSMBlockW));
    end;
    lfsr[0] := s0;
    lfsr[1] := s1;
    lfsr[2] := s2;
    lfsr[3] := s3;
    lfsr[4] := s4;
    lfsr[5] := s5;
    lfsr[6] := s6;
    lfsr[7] := s7;
    lfsr[8] := s8;
    lfsr[9] := s9;
    fsmr[1] := r1;
    fsmr[2] := r2;
  end;
end;


{$ifdef Q_OPT}
  {$ifdef OverflowChecks_on}
    {$Q+}
  {$endif}
{$endif}

{$ifdef RangeChecks_on}
  {$R+}
{$endif}
