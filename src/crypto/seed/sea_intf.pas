unit SEA_INTF;

(*************************************************************************

 DESCRIPTION     :  Interface unit for SEA_DLL

 REQUIREMENTS    :  D2-D7/D9-D10/D12, FPC

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     16.06.07  W.Ehrhardt  Initial version analog TF_INTF
 0.11     15.07.09  we          SEA_DLL_Version returns PAnsiChar, external 'SEA_DLL.DLL'
 0.12     26.07.10  we          Longint ILen, SEA_Err_Invalid_16Bit_Length
 0.13     27.07.10  we          Removed OMAC XL version
 0.14     28.07.10  we          SEA_CTR_Seek, SEA_CTR_Seek64
 0.15     31.07.10  we          SEA_CTR_Seek/64 via sea_seek.inc
**************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2007-2010 Wolfgang Ehrhardt

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
  SEA_Err_Invalid_Key_Size       = -1;  {Key size in bits not 128, 192, or 256}
  SEA_Err_Invalid_Length         = -3;  {No full block for cipher stealing}
  SEA_Err_Data_After_Short_Block = -4;  {Short block must be last}
  SEA_Err_MultipleIncProcs       = -5;  {More than one IncProc Setting}
  SEA_Err_NIL_Pointer            = -6;  {nil pointer to block with nonzero length}
  SEA_Err_CTR_SeekOffset         = -15; {Negative offset in SEA_CTR_Seek}
  SEA_Err_Invalid_16Bit_Length   = -20; {Pointer + Offset > $FFFF for 16 bit code}

type
  TSEARndKey = packed array[0..31]  of longint;  {Round key schedule}
  TSEABlock  = packed array[0..15]  of byte;     {128 bit block}
  PSEABlock  = ^TSEABlock;

type
  TSEAIncProc = procedure(var CTR: TSEABlock); {$ifdef USEDLL} stdcall; {$endif}
                 {user supplied IncCTR proc}
type
  TSEAContext = packed record
                 IV      : TSEABlock;   {IV or CTR              }
                 buf     : TSEABlock;   {Work buffer            }
                 bLen    : word;        {Bytes used in buf      }
                 Flag    : word;        {Bit 1: Short block     }
                 IncProc : TSEAIncProc; {Increment proc CTR-Mode}
                 RK      : TSEARndKey;  {Round keys             }
               end;

const
  SEABLKSIZE  = sizeof(TSEABlock);     {SEED block size in bytes}

type
  TSEA_EAXContext = packed record
                      HdrOMAC : TSEAContext; {Hdr OMAC1  context}
                      MsgOMAC : TSEAContext; {Msg OMAC1  context}
                      ctr_ctx : TSEAContext; {Msg SEACTR context}
                      NonceTag: TSEABlock;   {nonce tag         }
                      tagsize : word;        {tag size (unused) }
                      flags   : word;        {ctx flags (unused)}
                    end;


function  SEA_DLL_Version: PAnsiChar;
stdcall; external 'SEA_DLL.DLL' name 'SEA_DLL_Version';
  {-Return DLL version as PAnsiChar}



function  SEA_Init(const Key; KeyBits: word; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_Init';
  {-SEED context/round key initialization}

procedure SEA_Encrypt(var ctx: TSEAContext; const BI: TSEABlock; var BO: TSEABlock);
stdcall; external 'SEA_DLL.DLL' name 'SEA_Encrypt';
  {-encrypt one block (in ECB mode)}

procedure SEA_Decrypt(var ctx: TSEAContext; const BI: TSEABlock; var BO: TSEABlock);
stdcall; external 'SEA_DLL.DLL' name 'SEA_Decrypt';
  {-decrypt one block (in ECB mode)}

procedure SEA_XorBlock(const B1, B2: TSEABlock; var B3: TSEABlock);
stdcall; external 'SEA_DLL.DLL' name 'SEA_XorBlock';
  {-xor two blocks, result in third}

procedure SEA_Reset(var ctx: TSEAContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_Reset';
  {-Clears ctx fields bLen and Flag}

procedure SEA_SetFastInit(value: boolean);
stdcall; external 'SEA_DLL.DLL' name 'SEA_SetFastInit';
  {-set FastInit variable}

function  SEA_GetFastInit: boolean;
stdcall; external 'SEA_DLL.DLL' name 'SEA_GetFastInit';
  {-Returns FastInit variable}



function  SEA_CBC_Init(const Key; KeyBits: word; const IV: TSEABlock; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_CBC_Init';
  {-SEED key expansion, error if invalid key size, save IV}

procedure SEA_CBC_Reset(const IV: TSEABlock; var ctx: TSEAContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_CBC_Reset';
  {-Clears ctx fields bLen and Flag, save IV}

function  SEA_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_CBC_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  SEA_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_CBC_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  SEA_CFB_Init(const Key; KeyBits: word; const IV: TSEABlock; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_CFB_Init';
  {-SEED key expansion, error if invalid key size, encrypt IV}

procedure SEA_CFB_Reset(const IV: TSEABlock; var ctx: TSEAContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_CFB_Reset';
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SEA_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_CFB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB128 mode}

function  SEA_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_CFB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB128 mode}



function  SEA_CTR_Init(const Key; KeyBits: word; const CTR: TSEABlock; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_CTR_Init';
  {-SEED key expansion, error if inv. key size, encrypt CTR}

procedure SEA_CTR_Reset(const CTR: TSEABlock; var ctx: TSEAContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_CTR_Reset';
  {-Clears ctx fields bLen and Flag, encrypt CTR}

function  SEA_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_CTR_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  SEA_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_CTR_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  SEA_CTR_Seek(const iCTR: TSEABlock; SOL, SOH: longint; var ctx: TSEAContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in SEA_CTR_Init.}

{$ifdef HAS_INT64}
function SEA_CTR_Seek64(const iCTR: TSEABlock; SO: int64; var ctx: TSEAContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SO >= 0;}
  { iCTR is the initial CTR value for offset 0, i.e. the same as in SEA_CTR_Init.}
{$endif}

function  SEA_SetIncProc(IncP: TSEAIncProc; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_SetIncProc';
  {-Set user supplied IncCTR proc}

procedure SEA_IncMSBFull(var CTR: TSEABlock);
stdcall; external 'SEA_DLL.DLL' name 'SEA_IncMSBFull';
  {-Increment CTR[15]..CTR[0]}

procedure SEA_IncLSBFull(var CTR: TSEABlock);
stdcall; external 'SEA_DLL.DLL' name 'SEA_IncLSBFull';
  {-Increment CTR[0]..CTR[15]}

procedure SEA_IncMSBPart(var CTR: TSEABlock);
stdcall; external 'SEA_DLL.DLL' name 'SEA_IncMSBPart';
  {-Increment CTR[15]..CTR[8]}

procedure SEA_IncLSBPart(var CTR: TSEABlock);
stdcall; external 'SEA_DLL.DLL' name 'SEA_IncLSBPart';
  {-Increment CTR[0]..CTR[7]}



function  SEA_ECB_Init(const Key; KeyBits: word; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_ECB_Init';
  {-SEED key expansion, error if invalid key size}

procedure SEA_ECB_Reset(var ctx: TSEAContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_ECB_Reset';
  {-Clears ctx fields bLen and Flag}

function  SEA_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_ECB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  SEA_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_ECB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  SEA_OFB_Init(const Key; KeyBits: word; const IV: TSEABlock; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_OFB_Init';
  {-SEED key expansion, error if invalid key size, encrypt IV}

procedure SEA_OFB_Reset(const IV: TSEABlock; var ctx: TSEAContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_OFB_Reset';
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SEA_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_OFB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  SEA_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_OFB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}



function  SEA_OMAC_Init(const Key; KeyBits: word; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_OMAC_Init';
  {-OMAC init: SEED key expansion, error if inv. key size}

function  SEA_OMAC_Update(data: pointer; ILen: longint; var ctx: TSEAContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_OMAC_Update';
  {-OMAC data input, may be called more than once}

procedure SEA_OMAC_Final(var tag: TSEABlock; var ctx: TSEAContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_OMAC_Final';
  {-end data input, calculate OMAC=OMAC1 tag}

procedure SEA_OMAC1_Final(var tag: TSEABlock; var ctx: TSEAContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_OMAC1_Final';
  {-end data input, calculate OMAC1 tag}

procedure SEA_OMAC2_Final(var tag: TSEABlock; var ctx: TSEAContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_OMAC2_Final';
  {-end data input, calculate OMAC2 tag}



function SEA_EAX_Init(const Key; KBits: word; const nonce; nLen: word; var ctx: TSEA_EAXContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_EAX_Init';
  {-Init hdr and msg OMACs, setp SEACTR with nonce tag}

function SEA_EAX_Provide_Header(Hdr: pointer; hLen: word; var ctx: TSEA_EAXContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_EAX_Provide_Header';
  {-Supply a message header. The header "grows" with each call}

function SEA_EAX_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEA_EAXContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_EAX_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

function SEA_EAX_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEA_EAXContext): integer;
stdcall; external 'SEA_DLL.DLL' name 'SEA_EAX_Decrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

procedure SEA_EAX_Final(var tag: TSEABlock; var ctx: TSEA_EAXContext);
stdcall; external 'SEA_DLL.DLL' name 'SEA_EAX_Final';
  {-Compute EAX tag from context}


implementation

{$i sea_seek.inc}

end.
