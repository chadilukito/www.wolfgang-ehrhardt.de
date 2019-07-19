unit XT_INTV;


{$ifdef VirtualPascal}
  {$stdcall+}
{$else}
  Error('Interface unit for VirtualPascal');
{$endif}


(*************************************************************************

 DESCRIPTION     :  Interface unit for XT_DLL

 REQUIREMENTS    :  VirtualPascal

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.01.05  W.Ehrhardt  Initial version a la XT_INTV
 0.11     16.07.09  we          XT_DLL_Version returns PAnsiChar
 0.12     06.08.10  we          Longint ILen, XT_CTR_Seek via xt_seek.inc
**************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2005-2010 Wolfgang Ehrhardt

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


function  XT_DLL_Version: PAnsiChar;
  {-Return DLL version as PAnsiChar}

function  XT_Init(const Key; KeyBytes: word; var ctx: TXTContext): integer;
  {-XTEA context initialization}

procedure XT_Encrypt(var ctx: TXTContext; const BI: TXTBlock; var BO: TXTBlock);
  {-encrypt one block (in ECB mode)}

procedure XT_Decrypt(var ctx: TXTContext; const BI: TXTBlock; var BO: TXTBlock);
  {-decrypt one block (in ECB mode)}

procedure XT_XorBlock(const B1, B2: TXTBlock; var B3: TXTBlock);
  {-xor two blocks, result in third}

procedure XT_SetFastInit(value: boolean);
  {-set FastInit variable}

function  XT_GetFastInit: boolean;
  {-Returns FastInit variable}

function  XT_CBC_Init(const Key; KeyBytes: word; const IV: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size, save IV}

procedure XT_CBC_Reset(const IV: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, save IV}

function  XT_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  XT_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  XT_CFB_Init(const Key; KeyBytes: word; const IV: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size, encrypt IV}

procedure XT_CFB_Reset(const IV: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  XT_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB mode}

function  XT_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB mode}



function  XT_CTR_Init(const Key; KeyBytes: word; const CTR: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if inv. key size, encrypt CTR}

procedure XT_CTR_Reset(const CTR: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}

function  XT_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  XT_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  XT_CTR_Seek(const iCTR: TXTBlock; SOL, SOH: longint; var ctx: TXTContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in XT_CTR_Init.}

function  XT_SetIncProc(IncP: TXTIncProc; var ctx: TXTContext): integer;
  {-Set user supplied IncCTR proc}

procedure XT_IncMSBFull(var CTR: TXTBlock);
  {-Increment CTR[7]..CTR[0]}

procedure XT_IncLSBFull(var CTR: TXTBlock);
  {-Increment CTR[0]..CTR[7]}

procedure XT_IncMSBPart(var CTR: TXTBlock);
  {-Increment CTR[7]..CTR[4]}

procedure XT_IncLSBPart(var CTR: TXTBlock);
  {-Increment CTR[0]..CTR[3]}



function  XT_ECB_Init(const Key; KeyBytes: word; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size}

procedure XT_ECB_Reset(var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag}

function  XT_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  XT_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  XT_OFB_Init(const Key; KeyBits: word; const IV: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size, encrypt IV}

procedure XT_OFB_Reset(const IV: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  XT_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  XT_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}


implementation



function  XT_DLL_Version; external 'XT_DLL' name 'XT_DLL_Version';
function  XT_Init;        external 'XT_DLL' name 'XT_Init';
procedure XT_Encrypt;     external 'XT_DLL' name 'XT_Encrypt';
procedure XT_Decrypt;     external 'XT_DLL' name 'XT_Decrypt';
procedure XT_XorBlock;    external 'XT_DLL' name 'XT_XorBlock';
procedure XT_SetFastInit; external 'XT_DLL' name 'XT_SetFastInit';
function  XT_GetFastInit; external 'XT_DLL' name 'XT_GetFastInit';
function  XT_CBC_Init;    external 'XT_DLL' name 'XT_CBC_Init';
procedure XT_CBC_Reset;   external 'XT_DLL' name 'XT_CBC_Reset';
function  XT_CBC_Encrypt; external 'XT_DLL' name 'XT_CBC_Encrypt';
function  XT_CBC_Decrypt; external 'XT_DLL' name 'XT_CBC_Decrypt';
function  XT_CFB_Init;    external 'XT_DLL' name 'XT_CFB_Init';
procedure XT_CFB_Reset;   external 'XT_DLL' name 'XT_CFB_Reset';
function  XT_CFB_Encrypt; external 'XT_DLL' name 'XT_CFB_Encrypt';
function  XT_CFB_Decrypt; external 'XT_DLL' name 'XT_CFB_Decrypt';
function  XT_CTR_Init;    external 'XT_DLL' name 'XT_CTR_Init';
procedure XT_CTR_Reset;   external 'XT_DLL' name 'XT_CTR_Reset';
function  XT_CTR_Encrypt; external 'XT_DLL' name 'XT_CTR_Encrypt';
function  XT_CTR_Decrypt; external 'XT_DLL' name 'XT_CTR_Decrypt';
function  XT_SetIncProc;  external 'XT_DLL' name 'XT_SetIncProc';
procedure XT_IncMSBFull;  external 'XT_DLL' name 'XT_IncMSBFull';
procedure XT_IncLSBFull;  external 'XT_DLL' name 'XT_IncLSBFull';
procedure XT_IncMSBPart;  external 'XT_DLL' name 'XT_IncMSBPart';
procedure XT_IncLSBPart;  external 'XT_DLL' name 'XT_IncLSBPart';
function  XT_ECB_Init;    external 'XT_DLL' name 'XT_ECB_Init';
procedure XT_ECB_Reset;   external 'XT_DLL' name 'XT_ECB_Reset';
function  XT_ECB_Encrypt; external 'XT_DLL' name 'XT_ECB_Encrypt';
function  XT_ECB_Decrypt; external 'XT_DLL' name 'XT_ECB_Decrypt';
function  XT_OFB_Init;    external 'XT_DLL' name 'XT_OFB_Init';
procedure XT_OFB_Reset;   external 'XT_DLL' name 'XT_OFB_Reset';
function  XT_OFB_Encrypt; external 'XT_DLL' name 'XT_OFB_Encrypt';
function  XT_OFB_Decrypt; external 'XT_DLL' name 'XT_OFB_Decrypt';

{$define CONST}
{$i xt_seek.inc}

end.
