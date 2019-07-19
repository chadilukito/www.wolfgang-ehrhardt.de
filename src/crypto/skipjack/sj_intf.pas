unit SJ_INTF;

(*************************************************************************

 DESCRIPTION     :  Interface unit for SJ_DLL

 REQUIREMENTS    :  D2-D7/D9-D10/D12, FPC

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     03.06.09  W.Ehrhardt  Initial version a la XT_INTF
 0.11     16.07.09  we          SJ_DLL_Version returns PAnsiChar, 'SJ_DLL.DLL'
 0.12     06.08.10  we          Longint ILen, SJ_CTR_Seek/64 via sj_seek.inc
**************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2009-2010 Wolfgang Ehrhardt

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

{$i std.inc}

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
                {$ifdef UseDLL} stdcall; {$endif}
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


function  SJ_DLL_Version: PAnsiChar;
stdcall; external 'SJ_DLL.DLL' name 'SJ_DLL_Version';
  {-Return DLL version as PAnsiChar}



function  SJ_Init(const Key; KeyBytes: word; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_Init';
  {-SkipJack context initialization}

procedure SJ_Encrypt(var ctx: TSJContext; const BI: TSJBlock; var BO: TSJBlock);
stdcall; external 'SJ_DLL.DLL' name 'SJ_Encrypt';
  {-encrypt one block}

procedure SJ_Decrypt(var ctx: TSJContext; const BI: TSJBlock; var BO: TSJBlock);
stdcall; external 'SJ_DLL.DLL' name 'SJ_Decrypt';
  {-decrypt one block}

procedure SJ_XorBlock(const B1, B2: TSJBlock; var B3: TSJBlock);
stdcall; external 'SJ_DLL.DLL' name 'SJ_XorBlock';
  {-xor two blocks, result in third}

procedure SJ_SetFastInit(value: boolean);
stdcall; external 'SJ_DLL.DLL' name 'SJ_SetFastInit';
  {-set FastInit variable}

function  SJ_GetFastInit: boolean;
stdcall; external 'SJ_DLL.DLL' name 'SJ_GetFastInit';
  {-Returns FastInit variable}



function  SJ_CBC_Init(const Key; KeyBytes: word; const IV: TSJBlock; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_CBC_Init';
  {-SkipJack key expansion, error if invalid key size, save IV}

procedure SJ_CBC_Reset(const IV: TSJBlock; var ctx: TSJContext);
stdcall; external 'SJ_DLL.DLL' name 'SJ_CBC_Reset';
  {-Clears ctx fields bLen and Flag, save IV}

function  SJ_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_CBC_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  SJ_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_CBC_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  SJ_CFB_Init(const Key; KeyBytes: word; const IV: TSJBlock; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_CFB_Init';
  {-SkipJack key expansion, error if invalid key size, encrypt IV}

procedure SJ_CFB_Reset(const IV: TSJBlock; var ctx: TSJContext);
stdcall; external 'SJ_DLL.DLL' name 'SJ_CFB_Reset';
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SJ_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_CFB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB mode}

function  SJ_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_CFB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB mode}



function  SJ_CTR_Init(const Key; KeyBytes: word; const CTR: TSJBlock; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_CTR_Init';
  {-SkipJack key expansion, error if inv. key size, encrypt CTR}

procedure SJ_CTR_Reset(const CTR: TSJBlock; var ctx: TSJContext);
stdcall; external 'SJ_DLL.DLL' name 'SJ_CTR_Reset';
  {-Clears ctx fields bLen and Flag, encrypt CTR}

function  SJ_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_CTR_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  SJ_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_CTR_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  SJ_CTR_Seek(const iCTR: TSJBlock; SOL, SOH: longint; var ctx: TSJContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in SJ_CTR_Init.}

{$ifdef HAS_INT64}
function SJ_CTR_Seek64(const iCTR: TSJBlock; SO: int64; var ctx: TSJContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SO >= 0;}
  { iCTR is the initial CTR value for offset 0, i.e. the same as in SJ_CTR_Init.}
{$endif}

function  SJ_SetIncProc(IncP: TSJIncProc; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_SetIncProc';
  {-Set user supplied IncCTR proc}

procedure SJ_IncMSBFull(var CTR: TSJBlock);
stdcall; external 'SJ_DLL.DLL' name 'SJ_IncMSBFull';
  {-Increment CTR[7]..CTR[0]}

procedure SJ_IncLSBFull(var CTR: TSJBlock);
stdcall; external 'SJ_DLL.DLL' name 'SJ_IncLSBFull';
  {-Increment CTR[0]..CTR[7]}

procedure SJ_IncMSBPart(var CTR: TSJBlock);
stdcall; external 'SJ_DLL.DLL' name 'SJ_IncMSBPart';
  {-Increment CTR[7]..CTR[4]}

procedure SJ_IncLSBPart(var CTR: TSJBlock);
stdcall; external 'SJ_DLL.DLL' name 'SJ_IncLSBPart';
  {-Increment CTR[0]..CTR[3]}



function  SJ_ECB_Init(const Key; KeyBytes: word; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_ECB_Init';
  {-SkipJack key expansion, error if invalid key size}

procedure SJ_ECB_Reset(var ctx: TSJContext);
stdcall; external 'SJ_DLL.DLL' name 'SJ_ECB_Reset';
  {-Clears ctx fields bLen and Flag}

function  SJ_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_ECB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  SJ_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_ECB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  SJ_OFB_Init(const Key; KeyBits: word; const IV: TSJBlock; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_OFB_Init';
  {-SkipJack key expansion, error if invalid key size, encrypt IV}

procedure SJ_OFB_Reset(const IV: TSJBlock; var ctx: TSJContext);
stdcall; external 'SJ_DLL.DLL' name 'SJ_OFB_Reset';
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SJ_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_OFB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  SJ_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
stdcall; external 'SJ_DLL.DLL' name 'SJ_OFB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}


implementation


{$i sj_seek.inc}

end.
