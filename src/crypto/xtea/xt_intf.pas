unit XT_INTF;

(*************************************************************************

 DESCRIPTION     :  Interface unit for XT_DLL

 REQUIREMENTS    :  D2-D7/D9-D10/D12, FPC

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.01.05  W.Ehrhardt  Initial version a la BF_INTF
 0.11     16.07.09  we          XT_DLL_Version returns PAnsiChar, external 'XT_DLL.DLL'
 0.12     06.08.10  we          Longint ILen, XT_CTR_Seek/64 via xt_seek.inc
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
  TXTIncProc = procedure(var CTR: TXTBlock);   {user supplied IncCTR proc}
                {$ifdef UseDLL} stdcall; {$endif}

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
stdcall; external 'XT_DLL.DLL' name 'XT_DLL_Version';
  {-Return DLL version as PAnsiChar}


function  XT_Init(const Key; KeyBytes: word; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_Init';
  {-XTEA context initialization}

procedure XT_Encrypt(var ctx: TXTContext; const BI: TXTBlock; var BO: TXTBlock);
stdcall; external 'XT_DLL.DLL' name 'XT_Encrypt';
  {-encrypt one block (in ECB mode)}

procedure XT_Decrypt(var ctx: TXTContext; const BI: TXTBlock; var BO: TXTBlock);
stdcall; external 'XT_DLL.DLL' name 'XT_Decrypt';
  {-decrypt one block (in ECB mode)}

procedure XT_XorBlock(const B1, B2: TXTBlock; var B3: TXTBlock);
stdcall; external 'XT_DLL.DLL' name 'XT_XorBlock';
  {-xor two blocks, result in third}

procedure XT_SetFastInit(value: boolean);
stdcall; external 'XT_DLL.DLL' name 'XT_SetFastInit';
  {-set FastInit variable}

function  XT_GetFastInit: boolean;
stdcall; external 'XT_DLL.DLL' name 'XT_GetFastInit';
  {-Returns FastInit variable}



function  XT_CBC_Init(const Key; KeyBytes: word; const IV: TXTBlock; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_CBC_Init';
  {-XTEA key expansion, error if invalid key size, save IV}

procedure XT_CBC_Reset(const IV: TXTBlock; var ctx: TXTContext);
stdcall; external 'XT_DLL.DLL' name 'XT_CBC_Reset';
  {-Clears ctx fields bLen and Flag, save IV}

function  XT_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_CBC_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  XT_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_CBC_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  XT_CFB_Init(const Key; KeyBytes: word; const IV: TXTBlock; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_CFB_Init';
  {-XTEA key expansion, error if invalid key size, encrypt IV}

procedure XT_CFB_Reset(const IV: TXTBlock; var ctx: TXTContext);
stdcall; external 'XT_DLL.DLL' name 'XT_CFB_Reset';
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  XT_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_CFB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB mode}

function  XT_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_CFB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB mode}



function  XT_CTR_Init(const Key; KeyBytes: word; const CTR: TXTBlock; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_CTR_Init';
  {-XTEA key expansion, error if inv. key size, encrypt CTR}

procedure XT_CTR_Reset(const CTR: TXTBlock; var ctx: TXTContext);
stdcall; external 'XT_DLL.DLL' name 'XT_CTR_Reset';
  {-Clears ctx fields bLen and Flag, encrypt CTR}

function  XT_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_CTR_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  XT_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_CTR_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  XT_CTR_Seek(const iCTR: TXTBlock; SOL, SOH: longint; var ctx: TXTContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in XT_CTR_Init.}

{$ifdef HAS_INT64}
function XT_CTR_Seek64(const iCTR: TXTBlock; SO: int64; var ctx: TXTContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SO >= 0;}
  { iCTR is the initial CTR value for offset 0, i.e. the same as in XT_CTR_Init.}
{$endif}

function  XT_SetIncProc(IncP: TXTIncProc; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_SetIncProc';
  {-Set user supplied IncCTR proc}

procedure XT_IncMSBFull(var CTR: TXTBlock);
stdcall; external 'XT_DLL.DLL' name 'XT_IncMSBFull';
  {-Increment CTR[7]..CTR[0]}

procedure XT_IncLSBFull(var CTR: TXTBlock);
stdcall; external 'XT_DLL.DLL' name 'XT_IncLSBFull';
  {-Increment CTR[0]..CTR[7]}

procedure XT_IncMSBPart(var CTR: TXTBlock);
stdcall; external 'XT_DLL.DLL' name 'XT_IncMSBPart';
  {-Increment CTR[7]..CTR[4]}

procedure XT_IncLSBPart(var CTR: TXTBlock);
stdcall; external 'XT_DLL.DLL' name 'XT_IncLSBPart';
  {-Increment CTR[0]..CTR[3]}



function  XT_ECB_Init(const Key; KeyBytes: word; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_ECB_Init';
  {-XTEA key expansion, error if invalid key size}

procedure XT_ECB_Reset(var ctx: TXTContext);
stdcall; external 'XT_DLL.DLL' name 'XT_ECB_Reset';
  {-Clears ctx fields bLen and Flag}

function  XT_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_ECB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  XT_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_ECB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  XT_OFB_Init(const Key; KeyBits: word; const IV: TXTBlock; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_OFB_Init';
  {-XTEA key expansion, error if invalid key size, encrypt IV}

procedure XT_OFB_Reset(const IV: TXTBlock; var ctx: TXTContext);
stdcall; external 'XT_DLL.DLL' name 'XT_OFB_Reset';
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  XT_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_OFB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  XT_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
stdcall; external 'XT_DLL.DLL' name 'XT_OFB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}


implementation

{$i xt_seek.inc}

end.
