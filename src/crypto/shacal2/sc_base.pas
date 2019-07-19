unit SC_Base;

(*************************************************************************

 DESCRIPTION     :  SHACAL-2 basic routines

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12/D17, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  H.Handschuh, D.Naccache in shacal_tweak.ps,
                    https://www.cosic.esat.kuleuven.be/nessie/updatedPhase2Specs/SHACAL/shacal-tweak.zip

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     02.01.05  W.Ehrhardt  Initial BP7 a la BF_Base with SHA256 code
 0.11     02.01.05  we          Other compilers
 0.12     02.01.05  we          SC_XorBlock finished
 0.13     04.01.05  we          BASM16 with inline RB
 0.14     03.06.06  we          $R- for StrictLong, D9+: errors if $R+ even if warnings off
 0.15     06.08.10  we          SC_Err_CTR_SeekOffset, SC_Err_Invalid_16Bit_Length
 0.16     22.07.12  we          64-bit compatibility
 0.17     25.12.12  we          {$J+} if needed
 0.18     21.11.17  we          common code for CPUARM/BIT64
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2005-2012 Wolfgang Ehrhardt

 This software is provided 'as-is', without any express or implied warranty.
 In no event will the authors be held liable for any damages arising from
 the use of this software.

 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:

 1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software in
    a product, an acknowledgment in the product documentation would be
    appreciated but is not required.

 2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

 3. This notice may not be removed or altered from any source distribution.
----------------------------------------------------------------------------*)


{$i STD.INC}

interface

const
  SC_Err_Invalid_Key_Size       = -1;  {Key size in bytes <1 or >64}
  SC_Err_Invalid_Length         = -3;  {No full block for cipher stealing}
  SC_Err_Data_After_Short_Block = -4;  {Short block must be last}
  SC_Err_MultipleIncProcs       = -5;  {More than one IncProc Setting}
  SC_Err_NIL_Pointer            = -6;  {nil pointer to block with nonzero length}

  SC_Err_CTR_SeekOffset         = -15; {Negative offset in SC_CTR_Seek}
  SC_Err_Invalid_16Bit_Length   = -20; {Pointer + Offset > $FFFF for 16 bit code}

type
  TSCKeyArr  = packed array[0..63] of longint;
  TSCBlock   = packed array[0..31] of byte;
  TWA8       = packed array[0..7]  of longint;
  PSCBlock   = ^TSCBlock;

type
  TSCIncProc = procedure(var CTR: TSCBlock);   {user supplied IncCTR proc}
                {$ifdef DLL} stdcall; {$endif}
type
  TSCContext = packed record
                 RK      : TSCKeyArr;  {round key array        }
                 IV      : TSCBlock;   {IV or CTR              }
                 buf     : TSCBlock;   {Work buffer            }
                 bLen    : word;       {Bytes used in buf      }
                 Flag    : word;       {Bit 1: Short block     }
                 IncProc : TSCIncProc; {Increment proc CTR-Mode}
               end;

const
  SCBLKSIZE  = sizeof(TSCBlock);


{$ifdef CONST}

function  SC_Init(const Key; KeyBytes: word; var ctx: TSCContext): integer;
  {-SHACAL-2 context initialization}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_Encrypt(var ctx: TSCContext; const BI: TSCBlock; var BO: TSCBlock);
  {-encrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_Decrypt(var ctx: TSCContext; const BI: TSCBlock; var BO: TSCBlock);
  {-decrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_XorBlock(const B1, B2: TSCBlock; var B3: TSCBlock);
  {-xor two blocks, result in third}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  SC_Init(var Key; KeyBytes: word; var ctx: TSCContext): integer;
  {-SHACAL-2 context initialization}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_Encrypt(var ctx: TSCContext; var BI: TSCBlock; var BO: TSCBlock);
  {-encrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_Decrypt(var ctx: TSCContext; var BI: TSCBlock; var BO: TSCBlock);
  {-decrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_XorBlock(var B1, B2: TSCBlock; var B3: TSCBlock);
  {-xor two blocks, result in third}

{$endif}

procedure SC_Reset(var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag}

procedure SC_SetFastInit(value: boolean);
  {-set FastInit variable}
  {$ifdef DLL} stdcall; {$endif}

function  SC_GetFastInit: boolean;
  {-Returns FastInit variable}
  {$ifdef DLL} stdcall; {$endif}


implementation



{$ifdef D4Plus}
var
{$else}
{$ifdef J_OPT} {$J+} {$endif}
const
{$endif}
  FastInit : boolean = true;    {Clear only necessary context data at init}
                                {IV and buf remain uninitialized}


{---------------------------------------------------------------------------}
procedure SC_Reset(var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag}
begin
  with ctx do begin
    bLen :=0;
    Flag :=0;
  end;
end;


{---------------------------------------------------------------------------}
procedure SC_XorBlock({$ifdef CONST} const {$else} var {$endif} B1, B2: TSCBlock; var B3: TSCBlock);
  {-xor two blocks, result in third}
var
  a1: TWA8 absolute B1;
  a2: TWA8 absolute B2;
  a3: TWA8 absolute B3;
begin
  a3[0] := a1[0] xor a2[0];
  a3[1] := a1[1] xor a2[1];
  a3[2] := a1[2] xor a2[2];
  a3[3] := a1[3] xor a2[3];
  a3[4] := a1[4] xor a2[4];
  a3[5] := a1[5] xor a2[5];
  a3[6] := a1[6] xor a2[6];
  a3[7] := a1[7] xor a2[7];
end;


{--------------------------------------------------------------------------}
procedure SC_SetFastInit(value: boolean);
  {-set FastInit variable}
begin
  FastInit := value;
end;


{---------------------------------------------------------------------------}
function SC_GetFastInit: boolean;
  {-Returns FastInit variable}
begin
  SC_GetFastInit := FastInit;
end;


{$ifdef BIT64}
  {$define PurePascal}
{$endif}
{$ifdef CPUARM}
  {$define PurePascal}
{$endif}


{$ifndef BIT16}

{$ifdef PurePascal}

{---------------------------------------------------------------------------}
function RB(A: longint): longint;  {$ifdef HAS_INLINE} inline; {$endif}
  {-reverse byte order in longint}
begin
  RB := ((A and $FF) shl 24) or ((A and $FF00) shl 8) or ((A and $FF0000) shr 8) or ((A and longint($FF000000)) shr 24);
end;

{---------------------------------------------------------------------------}
function Sum1(x: longint): longint;  {$ifdef HAS_INLINE} inline; {$endif}
  {-Big sigma 1: RotRight(x,6) xor RotRight(x,11) xor RotRight(x,25)}
begin
  Sum1 := ((x shr 6) or (x shl 26)) xor  ((x shr 11) or (x shl 21))  xor  ((x shr 25) or (x shl 7));
end;

{---------------------------------------------------------------------------}
function Sum0(x: longint): longint;  {$ifdef HAS_INLINE} inline; {$endif}
  {-Big sigma 0: RotRight(x,2) xor RotRight(x,13) xor RotRight(x,22)}
begin
  Sum0 := ((x shr 2) or (x shl 30))  xor  ((x shr 13) or (x shl 19))  xor  ((x shr 22) or (x shl 10));
end;

{---------------------------------------------------------------------------}
procedure ExpandKeyBlock(var RK: TSCKeyArr);
  {-Expand round key, 0..15 already loaded in little endian format}
var
  A,B: longint;
  i: integer;
begin
  {Part 1: Transfer buffer with little -> big endian conversion}
  for i:=  0 to 15 do RK[i]:= RB(RK[i]);
  {Part 2: Calculate remaining "expanded message blocks"}
  for i:= 16 to 63 do begin
    A := RK[i-2];  A := ((A shr 17) or (A shl 15)) xor ((A shr 19) or (A shl 13)) xor (A shr 10);
    B := RK[i-15]; B := ((B shr  7) or (B shl 25)) xor ((B shr 18) or (B shl 14)) xor (B shr 3);
    RK[i]:= A + RK[i-7] + B + RK[i-16];
  end;
end;

{$else}

{---------------------------------------------------------------------------}
function RB(A: longint): longint; assembler;  {&frame-}
  {-reverse byte order in longint}
asm
  {$ifdef LoadArgs}
    mov eax,[A]
  {$endif}
    xchg al,ah
    rol  eax,16
    xchg al,ah
end;


{---------------------------------------------------------------------------}
function Sum0(x: longint): longint; assembler;   {&frame-}
  {-Big sigma 0: RotRight(x,2) xor RotRight(x,13) xor RotRight(x,22)}
asm
  {$ifdef LoadArgs}
    mov eax,[x]
  {$endif}
  mov  ecx,eax
  mov  edx,eax
  ror  eax,2
  ror  edx,13
  ror  ecx,22
  xor  eax,edx
  xor  eax,ecx
end;


{---------------------------------------------------------------------------}
function Sum1(x: longint): longint; assembler;  {&frame-}
  {-Big sigma 1: RotRight(x,6) xor RotRight(x,11) xor RotRight(x,25)}
asm
  {$ifdef LoadArgs}
    mov eax,[x]
  {$endif}
  mov  ecx,eax
  mov  edx,eax
  ror  eax,6
  ror  edx,11
  ror  ecx,25
  xor  eax,edx
  xor  eax,ecx
end;


{---------------------------------------------------------------------------}
procedure ExpandKeyBlock(var RK: TSCKeyArr);
  {-Expand round key, 0..15 already loaded in little endian format}
begin
  asm
     push  esi
     push  edi
     push  ebx
     mov   esi,[RK]
     mov   edx,[RK]
     {part 1: RK[i]:= RB(RK[i])}
     mov   ecx,16
@@1: mov   eax,[edx]
     xchg  al,ah
     rol   eax,16
     xchg  al,ah
     mov   [esi],eax
     add   esi,4
     add   edx,4
     dec   ecx
     jnz   @@1
     {part2: RK[i]:= LRot_1(RK[i-3] xor RK[i-8] xor RK[i-14] xor RK[i-16]);}
     mov   ecx,48
@@2: mov   edi,[esi-7*4]    {RK[i-7]}
     mov   eax,[esi-2*4]    {RK[i-2]}
     mov   ebx,eax          {Sig1: RR17 xor RR19 xor SR10}
     mov   edx,eax
     ror   eax,17
     ror   edx,19
     shr   ebx,10
     xor   eax,edx
     xor   eax,ebx
     add   edi,eax
     mov   eax,[esi-15*4]   {RK[i-15]}
     mov   ebx,eax          {Sig0: RR7 xor RR18 xor SR3}
     mov   edx,eax
     ror   eax,7
     ror   edx,18
     shr   ebx,3
     xor   eax,edx
     xor   eax,ebx
     add   eax,edi
     add   eax,[esi-16*4]  {RK[i-16]}
     mov   [esi],eax
     add   esi,4
     dec   ecx
     jnz   @@2
     pop   ebx
     pop   edi
     pop   esi
  end;
end;
{$endif}


{$else}

{$ifndef BASM16}

{TP5/5.5}


{---------------------------------------------------------------------------}
function RB(A: longint): longint;
  {-reverse byte order in longint}
inline(
  $58/          { pop  ax   }
  $5A/          { pop  dx   }
  $86/$C6/      { xchg dh,al}
  $86/$E2);     { xchg dl,ah}



{---------------------------------------------------------------------------}
function FS1(x: longint; c: integer): longint;
  {-Rotate x right, c<=16!!}
inline(
  $59/          {  pop  cx   }
  $58/          {  pop  ax   }
  $5A/          {  pop  dx   }
  $8B/$DA/      {  mov  bx,dx}
  $D1/$EB/      {L:shr  bx,1 }
  $D1/$D8/      {  rcr  ax,1 }
  $D1/$DA/      {  rcr  dx,1 }
  $49/          {  dec  cx   }
  $75/$F7);     {  jne  L    }


{---------------------------------------------------------------------------}
function FS2(x: longint; c: integer): longint;
  {-Rotate x right, c+16, c<16!!}
inline(
  $59/          {  pop  cx   }
  $5A/          {  pop  dx   }
  $58/          {  pop  ax   }
  $8B/$DA/      {  mov  bx,dx}
  $D1/$EB/      {L:shr  bx,1 }
  $D1/$D8/      {  rcr  ax,1 }
  $D1/$DA/      {  rcr  dx,1 }
  $49/          {  dec  cx   }
  $75/$F7);     {  jne  L    }


{---------------------------------------------------------------------------}
function ISHR(x: longint; c: integer): longint;
  {-Shift x right}
inline(
  $59/          {  pop  cx   }
  $58/          {  pop  ax   }
  $5A/          {  pop  dx   }
  $D1/$EA/      {L:shr  dx,1 }
  $D1/$D8/      {  rcr  ax,1 }
  $49/          {  dec  cx   }
  $75/$F9);     {  jne  L    }


{---------------------------------------------------------------------------}
function Sig0(x: longint): longint;
  {-Small sigma 0}
begin
  Sig0 := FS1(x,7) xor FS2(x,18-16) xor ISHR(x,3);
end;


{---------------------------------------------------------------------------}
function Sig1(x: longint): longint;
  {-Small sigma 1}
begin
  Sig1 := FS2(x,17-16) xor FS2(x,19-16) xor ISHR(x,10);
end;


{---------------------------------------------------------------------------}
function Sum0(x: longint): longint;
  {-Big sigma 0}
begin
  Sum0 := FS1(x,2) xor FS1(x,13) xor FS2(x,22-16);
end;


{---------------------------------------------------------------------------}
function Sum1(x: longint): longint;
  {-Big sigma 1}
begin
  Sum1 := FS1(x,6) xor FS1(x,11) xor FS2(x,25-16);
end;


{---------------------------------------------------------------------------}
procedure ExpandKeyBlock(var RK: TSCKeyArr);
  {-Expand round key, 0..15 already loaded in little endian format}
var
  i: integer;
begin
  {Part 1: Transfer buffer with little -> big endian conversion}
  for i:=  0 to 15 do RK[i]:= RB(RK[i]);
  {Part 2: Calculate remaining "expanded message blocks"}
  for i:= 16 to 63 do RK[i]:= Sig1(RK[i-2]) + RK[i-7] + Sig0(RK[i-15]) + RK[i-16];
end;

{$else}


{TP 6/7/Delphi1 for 386+}


{---------------------------------------------------------------------------}
function RB(A: longint): longint;
  {-reverse byte order in longint}
inline(
  $58/          { pop  ax   }
  $5A/          { pop  dx   }
  $86/$C6/      { xchg dh,al}
  $86/$E2);     { xchg dl,ah}



{---------------------------------------------------------------------------}
function Sum0(x: longint): longint; assembler;
  {-Big sigma 0: RotRight(x,2) xor RotRight(x,13) xor RotRight(x,22)}
asm
  db $66;  mov  ax,word ptr x
  db $66;  mov  bx,ax
  db $66;  mov  dx,ax
  db $66;  ror  ax,2
  db $66;  ror  dx,13
  db $66;  ror  bx,22
  db $66;  xor  ax,dx
  db $66;  xor  ax,bx
  db $66;  mov  dx,ax
  db $66;  shr  dx,16
end;


{---------------------------------------------------------------------------}
function Sum1(x: longint): longint; assembler;
  {-Big sigma 1: RotRight(x,6) xor RotRight(x,11) xor RotRight(x,25)}
asm
  db $66;  mov  ax,word ptr x
  db $66;  mov  bx,ax
  db $66;  mov  dx,ax
  db $66;  ror  ax,6
  db $66;  ror  dx,11
  db $66;  ror  bx,25
  db $66;  xor  ax,dx
  db $66;  xor  ax,bx
  db $66;  mov  dx,ax
  db $66;  shr  dx,16
end;


{---------------------------------------------------------------------------}
procedure ExpandKeyBlock(var RK: TSCKeyArr); assembler;
  {-Expand round key, 0..15 already loaded in little endian format}
asm
             push  ds
             {part 1: RK[i]:= RB(RK[i])}
             les   di,[RK]
             lds   si,[RK]
             mov   cx,16
@@1: db $66; mov   ax,es:[di]
             xchg  al,ah
     db $66; rol   ax,16
             xchg  al,ah
     db $66; mov   [si],ax
             add   si,4
             add   di,4
             dec   cx
             jnz   @@1
             {part 2: RK[i]:= Sig1(RK[i-2]) + RK[i-7] + Sig0(RK[i-15]) + RK[i-16];}
             mov   cx,48
@@2: db $66; mov   di,[si-7*4]    {RK[i-7]}
     db $66; mov   ax,[si-2*4]    {RK[i-2]}
     db $66; mov   bx,ax          {Sig1: RR17 xor RR19 xor SRx,10}
     db $66; mov   dx,ax
     db $66; ror   ax,17
     db $66; ror   dx,19
     db $66; shr   bx,10
     db $66; xor   ax,dx
     db $66; xor   ax,bx
     db $66; add   di,ax
     db $66; mov   ax,[si-15*4]   {RK[i-15]}
     db $66; mov   bx,ax          {Sig0: RR7 xor RR18 xor SR3}
     db $66; mov   dx,ax
     db $66; ror   ax,7
     db $66; ror   dx,18
     db $66; shr   bx,3
     db $66; xor   ax,dx
     db $66; xor   ax,bx
     db $66; add   ax,di
     db $66; add   ax,[si-16*4]   {RK[i-16]}
     db $66; mov   [si],ax
             add   si,4
             dec   cx
             jnz   @@2
             pop   ds
end;

{$endif BASM16}

{$endif BIT32}


{---------------------------------------------------------------------------}
procedure SC_Encrypt(var ctx: TSCContext; {$ifdef CONST} const {$else} var {$endif}  BI: TSCBlock; var BO: TSCBlock);
  {-encrypt one block (in ECB mode)}
var
  i: integer;
  A, B, C, D, E, F, G, H: longint;
begin
  with ctx do begin
    A := RB(TWA8(BI)[0]);
    B := RB(TWA8(BI)[1]);
    C := RB(TWA8(BI)[2]);
    D := RB(TWA8(BI)[3]);
    E := RB(TWA8(BI)[4]);
    F := RB(TWA8(BI)[5]);
    G := RB(TWA8(BI)[6]);
    H := RB(TWA8(BI)[7]);
    i := 0;
    repeat
      inc(H, Sum1(E) + ((E and (F xor G)) xor G) + RK[i  ]); inc(D,H); inc(H, Sum0(A) + ((A or B) and C or A and B));
      inc(G, Sum1(D) + ((D and (E xor F)) xor F) + RK[i+1]); inc(C,G); inc(G, Sum0(H) + ((H or A) and B or H and A));
      inc(F, Sum1(C) + ((C and (D xor E)) xor E) + RK[i+2]); inc(B,F); inc(F, Sum0(G) + ((G or H) and A or G and H));
      inc(E, Sum1(B) + ((B and (C xor D)) xor D) + RK[i+3]); inc(A,E); inc(E, Sum0(F) + ((F or G) and H or F and G));
      inc(D, Sum1(A) + ((A and (B xor C)) xor C) + RK[i+4]); inc(H,D); inc(D, Sum0(E) + ((E or F) and G or E and F));
      inc(C, Sum1(H) + ((H and (A xor B)) xor B) + RK[i+5]); inc(G,C); inc(C, Sum0(D) + ((D or E) and F or D and E));
      inc(B, Sum1(G) + ((G and (H xor A)) xor A) + RK[i+6]); inc(F,B); inc(B, Sum0(C) + ((C or D) and E or C and D));
      inc(A, Sum1(F) + ((F and (G xor H)) xor H) + RK[i+7]); inc(E,A); inc(A, Sum0(B) + ((B or C) and D or B and C));
      inc(i,8)
    until i>63;
    TWA8(BO)[0] := RB(A);
    TWA8(BO)[1] := RB(B);
    TWA8(BO)[2] := RB(C);
    TWA8(BO)[3] := RB(D);
    TWA8(BO)[4] := RB(E);
    TWA8(BO)[5] := RB(F);
    TWA8(BO)[6] := RB(G);
    TWA8(BO)[7] := RB(H);
  end;
end;


{---------------------------------------------------------------------------}
procedure SC_Decrypt(var ctx: TSCContext; {$ifdef CONST} const {$else} var {$endif}  BI: TSCBlock; var BO: TSCBlock);
  {-decrypt one block (in ECB mode)}
var
  i: integer;
  A, B, C, D, E, F, G, H: longint;
begin
  with ctx do begin
    A := RB(TWA8(BI)[0]);
    B := RB(TWA8(BI)[1]);
    C := RB(TWA8(BI)[2]);
    D := RB(TWA8(BI)[3]);
    E := RB(TWA8(BI)[4]);
    F := RB(TWA8(BI)[5]);
    G := RB(TWA8(BI)[6]);
    H := RB(TWA8(BI)[7]);
    i := 56;
    repeat
      dec(A, Sum0(B) + ((B or C) and D or B and C)); dec(E,A); dec(A, Sum1(F) + ((F and (G xor H)) xor H) + RK[i+7]);
      dec(B, Sum0(C) + ((C or D) and E or C and D)); dec(F,B); dec(B, Sum1(G) + ((G and (H xor A)) xor A) + RK[i+6]);
      dec(C, Sum0(D) + ((D or E) and F or D and E)); dec(G,C); dec(C, Sum1(H) + ((H and (A xor B)) xor B) + RK[i+5]);
      dec(D, Sum0(E) + ((E or F) and G or E and F)); dec(H,D); dec(D, Sum1(A) + ((A and (B xor C)) xor C) + RK[i+4]);
      dec(E, Sum0(F) + ((F or G) and H or F and G)); dec(A,E); dec(E, Sum1(B) + ((B and (C xor D)) xor D) + RK[i+3]);
      dec(F, Sum0(G) + ((G or H) and A or G and H)); dec(B,F); dec(F, Sum1(C) + ((C and (D xor E)) xor E) + RK[i+2]);
      dec(G, Sum0(H) + ((H or A) and B or H and A)); dec(C,G); dec(G, Sum1(D) + ((D and (E xor F)) xor F) + RK[i+1]);
      dec(H, Sum0(A) + ((A or B) and C or A and B)); dec(D,H); dec(H, Sum1(E) + ((E and (F xor G)) xor G) + RK[i  ]);
      dec(i,8)
    until i<0;
    TWA8(BO)[0] := RB(A);
    TWA8(BO)[1] := RB(B);
    TWA8(BO)[2] := RB(C);
    TWA8(BO)[3] := RB(D);
    TWA8(BO)[4] := RB(E);
    TWA8(BO)[5] := RB(F);
    TWA8(BO)[6] := RB(G);
    TWA8(BO)[7] := RB(H);
  end;
end;


{---------------------------------------------------------------------------}
function SC_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TSCContext): integer;
  {-SHACAL-2 context initialization}
var
  i: integer;
const
{$ifdef StrictLong}
  {$warnings off}
  {$R-} {avoid D9+ errors!}
{$endif}
  K: array[0..63] of longint = (
       $428a2f98, $71374491, $b5c0fbcf, $e9b5dba5,
       $3956c25b, $59f111f1, $923f82a4, $ab1c5ed5,
       $d807aa98, $12835b01, $243185be, $550c7dc3,
       $72be5d74, $80deb1fe, $9bdc06a7, $c19bf174,
       $e49b69c1, $efbe4786, $0fc19dc6, $240ca1cc,
       $2de92c6f, $4a7484aa, $5cb0a9dc, $76f988da,
       $983e5152, $a831c66d, $b00327c8, $bf597fc7,
       $c6e00bf3, $d5a79147, $06ca6351, $14292967,
       $27b70a85, $2e1b2138, $4d2c6dfc, $53380d13,
       $650a7354, $766a0abb, $81c2c92e, $92722c85,
       $a2bfe8a1, $a81a664b, $c24b8b70, $c76c51a3,
       $d192e819, $d6990624, $f40e3585, $106aa070,
       $19a4c116, $1e376c08, $2748774c, $34b0bcb5,
       $391c0cb3, $4ed8aa4a, $5b9cca4f, $682e6ff3,
       $748f82ee, $78a5636f, $84c87814, $8cc70208,
       $90befffa, $a4506ceb, $bef9a3f7, $c67178f2
     );
{$ifdef StrictLong}
  {$warnings on}
  {$ifdef RangeChecks_on}
    {$R+}
  {$endif}
{$endif}
begin
  if (KeyBytes<16) or (KeyBytes>64) then begin
    SC_Init := SC_Err_Invalid_Key_Size;
    exit;
  end;

  SC_Init := 0;
  if FastInit then begin
    {Clear only the necessary context data at init. IV and buf}
    {remain uninitialized, other fields are initialized below.}
    SC_Reset(ctx);
    {$ifdef CONST}
      ctx.IncProc := nil;
    {$else}
      {TP5-6 do not like IncProc := nil;}
      fillchar(ctx.IncProc, sizeof(ctx.IncProc), 0);
    {$endif}
    {Zero fill to 512 bit}
    for i:=KeyBytes div 4 to 63 do ctx.RK[i]:=0;
  end
  else fillchar(ctx, sizeof(ctx), 0);

  with ctx do begin
    {Calculate raw round key}
    {Move little endian user key}
    move(key, RK, KeyBytes);
    ExpandKeyBlock(RK);
    {Add SHA256 constants to raw round key}
    for i:=0 to 63 do inc(RK[i], K[i]);
  end;
end;

end.
