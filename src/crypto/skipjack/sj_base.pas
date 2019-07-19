unit SJ_Base;

(*************************************************************************

 DESCRIPTION     :  SkipJack basic routines

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12/D17, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  1 KB FTable

 DISPLAY MODE    :  ---

 REFERENCES      :  [1] SKIPJACK and KEA Algorithm Specification, Version 2.0, 29 May 1998
                        http://csrc.nist.gov/groups/ST/toolkit/documents/skipjack/skipjack.pdf
                    [2] Clarification to the Skipjack Algorithm Specification, May 9, 2002
                        http://csrc.nist.gov/groups/ST/toolkit/documents/skipjack/clarification.pdf

 REMARK          :  ---


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     24.05.09  W.Ehrhardt  Initial version a la XT_Base, straight from spec
 0.11     24.05.09  we          SJ_Encrypt: inline coding of function G
 0.12     24.05.09  we          SJ_Decrypt: inline coding of function G^-1
 0.13     24.05.09  we          SJ_Decrypt: improved Rule A^-1 coding
 0.14     24.05.09  we          TSJ2Long moved from interface to SJ_XorBlock
 0.15     24.05.09  we          Reference URL, renamed some variables
 0.16     24.05.09  we          Cardinal for BIT32 double decrypt speed
 0.17     24.05.09  we          FPC Fix: hi(word(wx))
 0.18     03.06.09  we          Use conventions from NIST clarification [2]
 0.19     06.08.10  we          SJ_Err_CTR_SeekOffset, SJ_Err_Invalid_16Bit_Length
 0.20     22.07.12  we          64-bit adjustments
 0.21     25.12.12  we          {$J+} if needed
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2009-2012 Wolfgang Ehrhardt

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
  SJ_Err_Invalid_Key_Size       = -1;  {Key size in bytes <> 10}
  SJ_Err_Invalid_Length         = -3;  {No full block for cipher stealing}
  SJ_Err_Data_After_Short_Block = -4;  {Short block must be last}
  SJ_Err_MultipleIncProcs       = -5;  {More than one IncProc Setting}
  SJ_Err_NIL_Pointer            = -6;  {nil pointer to block with nonzero length}

  SJ_Err_CTR_SeekOffset         = -15; {Invalid offset in SJ_CTR_Seek}
  SJ_Err_Invalid_16Bit_Length   = -20; {Pointer + Offset > $FFFF for 16 bit code}

type
  TSJBlock   = packed array[0..7] of byte;
  PSJBlock   = ^TSJBlock;
  TSJRKArray = packed array[0..9] of byte;

type
  TSJIncProc = procedure(var CTR: TSJBlock);   {user supplied IncCTR proc}
                {$ifdef DLL} stdcall; {$endif}
type
  TSJContext = packed record
                 CV      : TSJRKArray; {key array, 'cryptovariable' in spec}
                 IV      : TSJBlock;   {IV or CTR              }
                 buf     : TSJBlock;   {Work buffer            }
                 bLen    : word;       {Bytes used in buf      }
                 Flag    : word;       {Bit 1: Short block     }
                 IncProc : TSJIncProc; {Increment proc CTR-Mode}
               end;

const
  SJBLKSIZE  = sizeof(TSJBlock);


{$ifdef CONST}

function  SJ_Init(const Key; KeyBytes: word; var ctx: TSJContext): integer;
  {-SkipJack context initialization}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_Encrypt(var ctx: TSJContext; const BI: TSJBlock; var BO: TSJBlock);
  {-encrypt one block}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_Decrypt(var ctx: TSJContext; const BI: TSJBlock; var BO: TSJBlock);
  {-decrypt one block}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_XorBlock(const B1, B2: TSJBlock; var B3: TSJBlock);
  {-xor two blocks, result in third}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  SJ_Init(var Key; KeyBytes: word; var ctx: TSJContext): integer;
  {-SkipJack context initialization}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_Encrypt(var ctx: TSJContext; var BI: TSJBlock; var BO: TSJBlock);
  {-encrypt one block}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_Decrypt(var ctx: TSJContext; var BI: TSJBlock; var BO: TSJBlock);
  {-decrypt one block}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_XorBlock(var B1, B2: TSJBlock; var B3: TSJBlock);
  {-xor two blocks, result in third}

{$endif}

procedure SJ_Reset(var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag}

procedure SJ_SetFastInit(value: boolean);
  {-set FastInit variable}
  {$ifdef DLL} stdcall; {$endif}

function  SJ_GetFastInit: boolean;
  {-Returns FastInit variable}
  {$ifdef DLL} stdcall; {$endif}


implementation


{$ifdef D4Plus}
var
{$else}
{$ifdef J_OPT} {$J+} {$endif}
const
{$endif}
  FastInit: boolean = true;    {Clear only necessary context data at init}
                               {IV and buf remain uninitialized}

type
  TW4 = packed array[0..3] of word;

const
  FTable: array[byte] of byte = (
            $a3,$d7,$09,$83,$f8,$48,$f6,$f4,$b3,$21,$15,$78,$99,$b1,$af,$f9,
            $e7,$2d,$4d,$8a,$ce,$4c,$ca,$2e,$52,$95,$d9,$1e,$4e,$38,$44,$28,
            $0a,$df,$02,$a0,$17,$f1,$60,$68,$12,$b7,$7a,$c3,$e9,$fa,$3d,$53,
            $96,$84,$6b,$ba,$f2,$63,$9a,$19,$7c,$ae,$e5,$f5,$f7,$16,$6a,$a2,
            $39,$b6,$7b,$0f,$c1,$93,$81,$1b,$ee,$b4,$1a,$ea,$d0,$91,$2f,$b8,
            $55,$b9,$da,$85,$3f,$41,$bf,$e0,$5a,$58,$80,$5f,$66,$0b,$d8,$90,
            $35,$d5,$c0,$a7,$33,$06,$65,$69,$45,$00,$94,$56,$6d,$98,$9b,$76,
            $97,$fc,$b2,$c2,$b0,$fe,$db,$20,$e1,$eb,$d6,$e4,$dd,$47,$4a,$1d,
            $42,$ed,$9e,$6e,$49,$3c,$cd,$43,$27,$d2,$07,$d4,$de,$c7,$67,$18,
            $89,$cb,$30,$1f,$8d,$c6,$8f,$aa,$c8,$74,$dc,$c9,$5d,$5c,$31,$a4,
            $70,$88,$61,$2c,$9f,$0d,$2b,$87,$50,$82,$54,$64,$26,$7d,$03,$40,
            $34,$4b,$1c,$73,$d1,$c4,$fd,$3b,$cc,$fb,$7f,$ab,$e6,$3e,$5b,$a5,
            $ad,$04,$23,$9c,$14,$51,$22,$f0,$29,$79,$71,$7e,$ff,$8c,$0e,$e2,
            $0c,$ef,$bc,$72,$75,$6f,$37,$a1,$ec,$d3,$8e,$62,$8b,$86,$10,$e8,
            $08,$77,$11,$be,$92,$4f,$24,$c5,$32,$36,$9d,$cf,$f3,$a6,$bb,$ac,
            $5e,$6c,$a9,$13,$57,$25,$b5,$e3,$bd,$a8,$3a,$01,$05,$59,$2a,$46);

const
  nextk: array[0..9] of integer = (1, 2, 3, 4, 5, 6, 7, 8, 9, 0); {k+1 mod 10}
  prevk: array[0..9] of integer = (9, 0, 1, 2, 3, 4, 5, 6, 7, 8); {k-1 mod 10}


{---------------------------------------------------------------------------}
procedure SJ_Reset(var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag}
begin
  with ctx do begin
    bLen :=0;
    Flag :=0;
  end;
end;


{---------------------------------------------------------------------------}
procedure SJ_XorBlock({$ifdef CONST} const {$else} var {$endif} B1, B2: TSJBlock; var B3: TSJBlock);
  {-xor two blocks, result in third}
type
  TSJ2Long = packed record
               L,R: longint;
             end;
begin
  TSJ2Long(B3).L := TSJ2Long(B1).L xor TSJ2Long(B2).L;
  TSJ2Long(B3).R := TSJ2Long(B1).R xor TSJ2Long(B2).R;
end;


{--------------------------------------------------------------------------}
procedure SJ_SetFastInit(value: boolean);
  {-set FastInit variable}
begin
  FastInit := value;
end;


{---------------------------------------------------------------------------}
function SJ_GetFastInit: boolean;
  {-Returns FastInit variable}
begin
  SJ_GetFastInit := FastInit;
end;


{---------------------------------------------------------------------------}
procedure SJ_Encrypt(var ctx: TSJContext; {$ifdef CONST} const {$else} var {$endif}  BI: TSJBlock; var BO: TSJBlock);
  {-encrypt one block}
var
  {$ifndef BIT16}
    k: integer;
    w1,w2,w3,w4,r,t1,t2,g1,g2: cardinal;
  {$else}
    k: integer;
    w1,w2,w3,w4,r,t1,t2: word;
    g1,g2: byte;
  {$endif}
begin
  with ctx do begin
    w4 := TW4(BI)[0];
    w3 := TW4(BI)[1];
    w2 := TW4(BI)[2];
    w1 := TW4(BI)[3];
    k := 0;
    for r:=1 to 8 do begin
      {Rule A}
      g2 := byte(w1);
      g1 := hi(word(w1)) xor FTable[g2 xor CV[k]]; k := nextk[k];
      g2 := g2 xor FTable[g1 xor CV[k]]; k := nextk[k];
      g1 := g1 xor FTable[g2 xor CV[k]]; k := nextk[k];
      g2 := g2 xor FTable[g1 xor CV[k]]; k := nextk[k];
      t1 := word(g1) shl 8 or g2;
      w1 := t1 xor w4 xor r;
      w4 := w3;
      w3 := w2;
      w2 := t1;
    end;
    for r:=9 to 16 do begin
      {Rule B}
      g2 := byte(w1);
      g1 := hi(word(w1)) xor FTable[g2 xor CV[k]]; k := nextk[k];
      g2 := g2 xor FTable[g1 xor CV[k]]; k := nextk[k];
      g1 := g1 xor FTable[g2 xor CV[k]]; k := nextk[k];
      g2 := g2 xor FTable[g1 xor CV[k]]; k := nextk[k];
      t1 := word(g1) shl 8 or g2;
      t2 := w4;
      w4 := w3;
      w3 := w1 xor w2 xor r;
      w1 := t2;
      w2 := t1;
    end;
    for r:=17 to 24 do begin
      {Rule A}
      g2 := byte(w1);
      g1 := hi(word(w1)) xor FTable[g2 xor CV[k]]; k := nextk[k];
      g2 := g2 xor FTable[g1 xor CV[k]]; k := nextk[k];
      g1 := g1 xor FTable[g2 xor CV[k]]; k := nextk[k];
      g2 := g2 xor FTable[g1 xor CV[k]]; k := nextk[k];
      t1 := word(g1) shl 8 or g2;
      w1 := t1 xor w4 xor r;
      w4 := w3;
      w3 := w2;
      w2 := t1;
    end;
    for r:=25 to 32 do begin
      {Rule B}
      g2 := byte(w1);
      g1 := hi(word(w1)) xor FTable[g2 xor CV[k]]; k := nextk[k];
      g2 := g2 xor FTable[g1 xor CV[k]]; k := nextk[k];
      g1 := g1 xor FTable[g2 xor CV[k]]; k := nextk[k];
      g2 := g2 xor FTable[g1 xor CV[k]]; k := nextk[k];
      t1 := word(g1) shl 8 or g2;
      t2 := w4;
      w4 := w3;
      w3 := w1 xor w2 xor r;
      w1 := t2;
      w2 := t1;
    end;
    TW4(BO)[0] := word(w4);
    TW4(BO)[1] := word(w3);
    TW4(BO)[2] := word(w2);
    TW4(BO)[3] := word(w1);
 end;
end;


{---------------------------------------------------------------------------}
procedure SJ_Decrypt(var ctx: TSJContext; {$ifdef CONST} const {$else} var {$endif}  BI: TSJBlock; var BO: TSJBlock);
  {-decrypt one block}
var
  {$ifndef BIT16}
    k: integer;
    w1,w2,w3,w4,r,t1,g1,g2: cardinal;
  {$else}
    k: integer;
    w1,w2,w3,w4,r,t1: word;
    g1,g2: byte;
  {$endif}
begin
  with ctx do begin
    w4 := TW4(BI)[0];
    w3 := TW4(BI)[1];
    w2 := TW4(BI)[2];
    w1 := TW4(BI)[3];
    k := 8;
    for r:=32 downto 25 do begin
      {Rule B^-1}
      g1 := hi(word(w2));
      k  := prevk[k];  g2 := byte(w2) xor FTable[g1 xor CV[k]];
      k  := prevk[k];  g1 := g1 xor FTable[g2 xor CV[k]];
      k  := prevk[k];  g2 := g2 xor FTable[g1 xor CV[k]];
      k  := prevk[k];  g1 := g1 xor FTable[g2 xor CV[k]];
      t1 := word(g1) shl 8 or g2;
      w2 := t1 xor w3 xor r;
      w3 := w4;
      w4 := w1;
      w1 := t1;
    end;
    for r:=24 downto 17 do begin
      {Rule A^-1}
      g1 := hi(word(w2));
      k  := prevk[k];  g2 := byte(w2) xor FTable[g1 xor CV[k]];
      k  := prevk[k];  g1 := g1 xor FTable[g2 xor CV[k]];
      k  := prevk[k];  g2 := g2 xor FTable[g1 xor CV[k]];
      k  := prevk[k];  g1 := g1 xor FTable[g2 xor CV[k]];
      t1 := w1 xor w2 xor r;
      w1 := word(g1) shl 8 or g2;
      w2 := w3;
      w3 := w4;
      w4 := t1;
    end;
    for r:=16 downto 9 do begin
      {Rule B^-1}
      g1 := hi(word(w2));
      k  := prevk[k];  g2 := byte(w2) xor FTable[g1 xor CV[k]];
      k  := prevk[k];  g1 := g1 xor FTable[g2 xor CV[k]];
      k  := prevk[k];  g2 := g2 xor FTable[g1 xor CV[k]];
      k  := prevk[k];  g1 := g1 xor FTable[g2 xor CV[k]];
      t1 := word(g1) shl 8 or g2;
      w2 := t1 xor w3 xor r;
      w3 := w4;
      w4 := w1;
      w1 := t1;
    end;
    for r:=8 downto 1 do begin
      {Rule A^-1}
      g1 := hi(word(w2));
      k  := prevk[k];  g2 := byte(w2) xor FTable[g1 xor CV[k]];
      k  := prevk[k];  g1 := g1 xor FTable[g2 xor CV[k]];
      k  := prevk[k];  g2 := g2 xor FTable[g1 xor CV[k]];
      k  := prevk[k];  g1 := g1 xor FTable[g2 xor CV[k]];
      t1 := w1 xor w2 xor r;
      w1 := word(g1) shl 8 or g2;
      w2 := w3;
      w3 := w4;
      w4 := t1;
    end;
    TW4(BO)[0] := word(w4);
    TW4(BO)[1] := word(w3);
    TW4(BO)[2] := word(w2);
    TW4(BO)[3] := word(w1);
 end;
end;


{---------------------------------------------------------------------------}
function SJ_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TSJContext): integer;
  {-SkipJack context initialization}
var
  i: integer;
begin
  SJ_Init := 0;

  if FastInit then begin
    {Clear only the necessary context data at init. IV and buf}
    {remain uninitialized, other fields are initialized below.}
    SJ_Reset(ctx);
    {$ifdef CONST}
      ctx.IncProc := nil;
    {$else}
      {TP5-6 do not like IncProc := nil;}
      fillchar(ctx.IncProc, sizeof(ctx.IncProc), 0);
    {$endif}
  end
  else fillchar(ctx, sizeof(ctx), 0);

  if KeyBytes<>10 then begin
    SJ_Init := SJ_Err_Invalid_Key_Size;
    exit;
  end;
  for i:=0 to 9 do ctx.CV[i] := TSJRKArray(Key)[9-i];
end;

end.

