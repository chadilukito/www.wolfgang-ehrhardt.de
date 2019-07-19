unit XT_Base;

(*************************************************************************

 DESCRIPTION     :  XTEA basic routines

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D12/D17-D18/D25S, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  Roger M. Needham and David J. Wheeler: Tea extensions
                    ftp://ftp.cl.cam.ac.uk/users/djw3/xtea.ps

 REMARK          :  Number of rounds is hardcoded to 32


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.01.05  W.Ehrhardt  Initial version a la BF_Base
 0.11     01.01.05  we          BASM16 inline
 0.12     01.01.05  we          BIT16: XT_Init mit sumw
 0.13     04.01.05  we          with RB and Idx, compatible with Botan
 0.14     04.01.05  we          load K with RB(Key) only once
 0.15     06.08.10  we          XT_Err_CTR_SeekOffset, XT_Err_Invalid_16Bit_Length
 0.16     22.07.12  we          64-bit adjustments
 0.17     25.12.12  we          {$J+} if needed
 0.18     19.11.17  we          RB for CPUARM
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2005-2017 Wolfgang Ehrhardt

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
  XT_Err_Invalid_Key_Size       = -1;  {Key size in bytes <1 or >56}
  XT_Err_Invalid_Length         = -3;  {No full block for cipher stealing}
  XT_Err_Data_After_Short_Block = -4;  {Short block must be last}
  XT_Err_MultipleIncProcs       = -5;  {More than one IncProc Setting}
  XT_Err_NIL_Pointer            = -6;  {nil pointer to block with nonzero length}

  XT_Err_CTR_SeekOffset         = -15; {Invalid offset in XT_CTR_Seek}
  XT_Err_Invalid_16Bit_Length   = -20; {Pointer + Offset > $FFFF for 16 bit code}

type
  TXTBlock   = packed array[0..7] of byte;
  PXTBlock   = ^TXTBlock;
  TXTRKArray = packed array[0..31] of longint;

type
  TXT2Long   = packed record
                 L,R: longint;
               end;
type
  TXTIncProc = procedure(var CTR: TXTBlock);   {user supplied IncCTR proc}
                {$ifdef DLL} stdcall; {$endif}
type
  TXTContext = packed record
                 XA,XB   : TXTRKArray; {round key arrays       }
                 IV      : TXTBlock;   {IV or CTR              }
                 buf     : TXTBlock;   {Work buffer            }
                 bLen    : word;       {Bytes used in buf      }
                 Flag    : word;       {Bit 1: Short block     }
                 IncProc : TXTIncProc; {Increment proc CTR-Mode}
               end;

const
  XTBLKSIZE  = sizeof(TXTBlock);


{$ifdef CONST}

function  XT_Init(const Key; KeyBytes: word; var ctx: TXTContext): integer;
  {-XTEA context initialization}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_Encrypt(var ctx: TXTContext; const BI: TXTBlock; var BO: TXTBlock);
  {-encrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_Decrypt(var ctx: TXTContext; const BI: TXTBlock; var BO: TXTBlock);
  {-decrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_XorBlock(const B1, B2: TXTBlock; var B3: TXTBlock);
  {-xor two blocks, result in third}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  XT_Init(var Key; KeyBytes: word; var ctx: TXTContext): integer;
  {-XTEA context initialization}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_Encrypt(var ctx: TXTContext; var BI: TXTBlock; var BO: TXTBlock);
  {-encrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_Decrypt(var ctx: TXTContext; var BI: TXTBlock; var BO: TXTBlock);
  {-decrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_XorBlock(var B1, B2: TXTBlock; var B3: TXTBlock);
  {-xor two blocks, result in third}

{$endif}

procedure XT_Reset(var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag}

procedure XT_SetFastInit(value: boolean);
  {-set FastInit variable}
  {$ifdef DLL} stdcall; {$endif}

function  XT_GetFastInit: boolean;
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


{$ifndef BIT16}
{------- 32/64-bit code --------}
{$ifdef BIT64}
{---------------------------------------------------------------------------}
function RB(A: longint): longint;  {$ifdef HAS_INLINE} inline; {$endif}
  {-reverse byte order in longint}
begin
  RB := ((A and $FF) shl 24) or ((A and $FF00) shl 8) or ((A and $FF0000) shr 8) or ((A and longint($FF000000)) shr 24);
end;
{$else}
 {$ifdef CPUARM}
   {---------------------------------------------------------------------------}
   function RB(A: longint): longint;  {$ifdef HAS_INLINE} inline; {$endif}
     {-reverse byte order in longint}
   begin
     RB := ((A and $FF) shl 24) or ((A and $FF00) shl 8) or ((A and $FF0000) shr 8) or ((A and longint($FF000000)) shr 24);
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
 {$endif}

{$endif}

{$else}
{---------------------------------------------------------------------------}
function RB(A: longint): longint;
  {-reverse byte order in longint}
inline(
  $58/          { pop  ax   }
  $5A/          { pop  dx   }
  $86/$C6/      { xchg dh,al}
  $86/$E2);     { xchg dl,ah}
{$endif}



{---------------------------------------------------------------------------}
procedure XT_Reset(var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag}
begin
  with ctx do begin
    bLen :=0;
    Flag :=0;
  end;
end;



{---------------------------------------------------------------------------}
procedure XT_XorBlock({$ifdef CONST} const {$else} var {$endif} B1, B2: TXTBlock; var B3: TXTBlock);
  {-xor two blocks, result in third}
begin
  TXT2Long(B3).L := TXT2Long(B1).L xor TXT2Long(B2).L;
  TXT2Long(B3).R := TXT2Long(B1).R xor TXT2Long(B2).R;
end;



{--------------------------------------------------------------------------}
procedure XT_SetFastInit(value: boolean);
  {-set FastInit variable}
begin
  FastInit := value;
end;


{---------------------------------------------------------------------------}
function XT_GetFastInit: boolean;
  {-Returns FastInit variable}
begin
  XT_GetFastInit := FastInit;
end;



{$ifdef BASM16}
{---------------------------------------------------------------------------}
function XTR(y: longint): longint;
  {returns ((y shl 4) xor (y shr 5)) + y}
inline(
 $66/$58/            {pop    eax    }
 $66/$8B/$D0/        {mov    edx,eax}
 $66/$C1/$E2/$04/    {shl    edx,4  }
 $66/$8B/$C8/        {mov    ecx,eax}
 $66/$C1/$E9/$05/    {shr    ecx,5  }
 $66/$33/$D1/        {xor    edx,ecx}
 $66/$03/$C2/        {add    eax,edx}
 $66/$8B/$D0/        {mov    edx,eax}
 $66/$C1/$EA/$10);   {shr    edx,16 }
{$endif}



{---------------------------------------------------------------------------}
procedure XT_Encrypt(var ctx: TXTContext; {$ifdef CONST} const {$else} var {$endif}  BI: TXTBlock; var BO: TXTBlock);
  {-encrypt one block (in ECB mode)}
var
  y, z: longint;
  i: integer;
begin
  with ctx do begin
    y := RB(TXT2Long(BI).L);
    z := RB(TXT2Long(BI).R);
    for i:=0 to 31 do begin
      {$ifdef BASM16}
        inc(y, XTR(z) xor XA[i]);
        inc(z, XTR(y) xor XB[i]);
      {$else}
        inc(y, ((((z shl 4) xor (z shr 5)) + z) xor XA[i]));
        inc(z, ((((y shl 4) xor (y shr 5)) + y) xor XB[i]));
      {$endif}
    end;
    TXT2Long(BO).L := RB(y);
    TXT2Long(BO).R := RB(z);
 end;
end;



{---------------------------------------------------------------------------}
procedure XT_Decrypt(var ctx: TXTContext; {$ifdef CONST} const {$else} var {$endif}  BI: TXTBlock; var BO: TXTBlock);
  {-decrypt one block (in ECB mode)}
var
  y, z: longint;
  i: integer;
begin
  with ctx do begin
    y := RB(TXT2Long(BI).L);
    z := RB(TXT2Long(BI).R);
    for i:=31 downto 0 do begin
      {$ifdef BASM16}
        dec(z, XTR(y) xor XB[i]);
        dec(y, XTR(z) xor XA[i]);
      {$else}
        dec(z, ((((y shl 4) xor (y shr 5)) + y) xor XB[i]));
        dec(y, ((((z shl 4) xor (z shr 5)) + z) xor XA[i]));
      {$endif}
    end;
    TXT2Long(BO).L := RB(y);
    TXT2Long(BO).R := RB(z);
 end;
end;



{---------------------------------------------------------------------------}
function XT_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TXTContext): integer;
  {-XTEA context initialization}
type
  TWA4 = array[0..3] of longint;
var
  K: TWA4;
  i: integer;
  sum: longint;
{$ifdef BIT16}
  idx: word absolute sum;
{$else}
  idx: longint absolute sum;
{$endif}

begin
  XT_Init := 0;

  if FastInit then begin
    {Clear only the necessary context data at init. IV and buf}
    {remain uninitialized, other fields are initialized below.}
    XT_Reset(ctx);
    {$ifdef CONST}
      ctx.IncProc := nil;
    {$else}
      {TP5-6 do not like IncProc := nil;}
      fillchar(ctx.IncProc, sizeof(ctx.IncProc), 0);
    {$endif}
  end
  else fillchar(ctx, sizeof(ctx), 0);

  if KeyBytes<>16 then begin
    XT_Init := XT_Err_Invalid_Key_Size;
    exit;
  end;

  with ctx do begin
    sum := 0;
    for i:=0 to 3 do K[i] := RB(TWA4(Key)[i]);
    for i:=0 to 31 do begin
      XA[i] := sum + K[idx and 3];
      inc(sum, longint($9E3779B9));
      XB[i] := sum + K[(idx shr 11) and 3];
    end;
  end;
end;

end.

