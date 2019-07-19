unit SEA_INTV;


{$ifdef VirtualPascal}
  {$stdcall+}
{$else}
  Error('Interface unit for VirtualPascal');
{$endif}

(*************************************************************************

 DESCRIPTION     :  Interface unit for SEA_DLL

 REQUIREMENTS    :  VirtualPascal

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     16.06.07  W.Ehrhardt  Initial version analog TF_INTV
 0.11     15.07.09  we          SEA_DLL_Version returns PAnsiChar
 0.12     26.07.10  we          Longint ILen, SEA_Err_Invalid_16Bit_Length
 0.13     27.07.10  we          Removed OMAC XL version
 0.14     28.07.10  we          SEA_CTR_Seek
 0.15     31.07.10  we          SEA_CTR_Seek via sea_seek.inc
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
  TSEAIncProc = procedure(var CTR: TSEABlock);   {user supplied IncCTR proc}
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
  {-Return DLL version as PAnsiChar}



function  SEA_Init(const Key; KeyBits: word; var ctx: TSEAContext): integer;
  {-SEED context/round key initialization}

procedure SEA_Encrypt(var ctx: TSEAContext; const BI: TSEABlock; var BO: TSEABlock);
  {-encrypt one block (in ECB mode)}

procedure SEA_Decrypt(var ctx: TSEAContext; const BI: TSEABlock; var BO: TSEABlock);
  {-decrypt one block (in ECB mode)}

procedure SEA_XorBlock(const B1, B2: TSEABlock; var B3: TSEABlock);
  {-xor two blocks, result in third}

procedure SEA_Reset(var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag}

procedure SEA_SetFastInit(value: boolean);
  {-set FastInit variable}

function  SEA_GetFastInit: boolean;
  {-Returns FastInit variable}



function  SEA_CBC_Init(const Key; KeyBits: word; const IV: TSEABlock; var ctx: TSEAContext): integer;
  {-SEA key expansion, error if invalid key size, save IV}

procedure SEA_CBC_Reset(const IV: TSEABlock; var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag, save IV}

function  SEA_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  SEA_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  SEA_CFB_Init(const Key; KeyBits: word; const IV: TSEABlock; var ctx: TSEAContext): integer;
  {-SEA key expansion, error if invalid key size, encrypt IV}

procedure SEA_CFB_Reset(const IV: TSEABlock; var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SEA_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB128 mode}

function  SEA_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB128 mode}



function  SEA_CTR_Init(const Key; KeyBits: word; const CTR: TSEABlock; var ctx: TSEAContext): integer;
  {-SEA key expansion, error if inv. key size, encrypt CTR}

procedure SEA_CTR_Reset(const CTR: TSEABlock; var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}

function  SEA_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  SEA_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  SEA_CTR_Seek(const iCTR: TSEABlock; SOL, SOH: longint; var ctx: TSEAContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in SEA_CTR_Init.}

function  SEA_SetIncProc(IncP: TSEAIncProc; var ctx: TSEAContext): integer;
  {-Set user supplied IncCTR proc}

procedure SEA_IncMSBFull(var CTR: TSEABlock);
  {-Increment CTR[15]..CTR[0]}

procedure SEA_IncLSBFull(var CTR: TSEABlock);
  {-Increment CTR[0]..CTR[15]}

procedure SEA_IncMSBPart(var CTR: TSEABlock);
  {-Increment CTR[15]..CTR[8]}

procedure SEA_IncLSBPart(var CTR: TSEABlock);
  {-Increment CTR[0]..CTR[7]}



function  SEA_ECB_Init(const Key; KeyBits: word; var ctx: TSEAContext): integer;
  {-SEA key expansion, error if invalid key size}

procedure SEA_ECB_Reset(var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag}

function  SEA_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  SEA_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  SEA_OFB_Init(const Key; KeyBits: word; const IV: TSEABlock; var ctx: TSEAContext): integer;
  {-SEA key expansion, error if invalid key size, encrypt IV}

procedure SEA_OFB_Reset(const IV: TSEABlock; var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SEA_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  SEA_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}



function  SEA_OMAC_Init(const Key; KeyBits: word; var ctx: TSEAContext): integer;
  {-OMAC init: SEA key expansion, error if inv. key size}

function  SEA_OMAC_Update(data: pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-OMAC data input, may be called more than once}

procedure SEA_OMAC_Final(var tag: TSEABlock; var ctx: TSEAContext);
  {-end data input, calculate OMAC=OMAC1 tag}

procedure SEA_OMAC1_Final(var tag: TSEABlock; var ctx: TSEAContext);
  {-end data input, calculate OMAC1 tag}

procedure SEA_OMAC2_Final(var tag: TSEABlock; var ctx: TSEAContext);
  {-end data input, calculate OMAC2 tag}




function SEA_EAX_Init(const Key; KBits: word; const nonce; nLen: word; var ctx: TSEA_EAXContext): integer;
  {-Init hdr and msg OMACs, setup SEACTR with nonce tag}

function SEA_EAX_Provide_Header(Hdr: pointer; hLen: word; var ctx: TSEA_EAXContext): integer;
  {-Supply a message header. The header "grows" with each call}

function SEA_EAX_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEA_EAXContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

function SEA_EAX_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEA_EAXContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

procedure SEA_EAX_Final(var tag: TSEABlock; var ctx: TSEA_EAXContext);
  {-Compute EAX tag from context}


implementation


function  SEA_DLL_Version; external 'SEA_DLL' name 'SEA_DLL_Version';
function  SEA_Init;        external 'SEA_DLL' name 'SEA_Init';
procedure SEA_Encrypt;     external 'SEA_DLL' name 'SEA_Encrypt';
procedure SEA_Decrypt;     external 'SEA_DLL' name 'SEA_Decrypt';
procedure SEA_XorBlock;    external 'SEA_DLL' name 'SEA_XorBlock';
procedure SEA_Reset;       external 'SEA_DLL' name 'SEA_Reset';
procedure SEA_SetFastInit; external 'SEA_DLL' name 'SEA_SetFastInit';
function  SEA_GetFastInit; external 'SEA_DLL' name 'SEA_GetFastInit';

function  SEA_CBC_Init;    external 'SEA_DLL' name 'SEA_CBC_Init';
procedure SEA_CBC_Reset;   external 'SEA_DLL' name 'SEA_CBC_Reset';
function  SEA_CBC_Encrypt; external 'SEA_DLL' name 'SEA_CBC_Encrypt';
function  SEA_CBC_Decrypt; external 'SEA_DLL' name 'SEA_CBC_Decrypt';

function  SEA_CFB_Init;    external 'SEA_DLL' name 'SEA_CFB_Init';
procedure SEA_CFB_Reset;   external 'SEA_DLL' name 'SEA_CFB_Reset';
function  SEA_CFB_Encrypt; external 'SEA_DLL' name 'SEA_CFB_Encrypt';
function  SEA_CFB_Decrypt; external 'SEA_DLL' name 'SEA_CFB_Decrypt';

function  SEA_CTR_Init;    external 'SEA_DLL' name 'SEA_CTR_Init';
procedure SEA_CTR_Reset;   external 'SEA_DLL' name 'SEA_CTR_Reset';
function  SEA_CTR_Encrypt; external 'SEA_DLL' name 'SEA_CTR_Encrypt';
function  SEA_CTR_Decrypt; external 'SEA_DLL' name 'SEA_CTR_Decrypt';
function  SEA_SetIncProc;  external 'SEA_DLL' name 'SEA_SetIncProc';
procedure SEA_IncMSBFull;  external 'SEA_DLL' name 'SEA_IncMSBFull';
procedure SEA_IncLSBFull;  external 'SEA_DLL' name 'SEA_IncLSBFull';
procedure SEA_IncMSBPart;  external 'SEA_DLL' name 'SEA_IncMSBPart';
procedure SEA_IncLSBPart;  external 'SEA_DLL' name 'SEA_IncLSBPart';

function  SEA_ECB_Init;    external 'SEA_DLL' name 'SEA_ECB_Init';
procedure SEA_ECB_Reset;   external 'SEA_DLL' name 'SEA_ECB_Reset';
function  SEA_ECB_Encrypt; external 'SEA_DLL' name 'SEA_ECB_Encrypt';
function  SEA_ECB_Decrypt; external 'SEA_DLL' name 'SEA_ECB_Decrypt';

function  SEA_OFB_Init;    external 'SEA_DLL' name 'SEA_OFB_Init';
procedure SEA_OFB_Reset;   external 'SEA_DLL' name 'SEA_OFB_Reset';
function  SEA_OFB_Encrypt; external 'SEA_DLL' name 'SEA_OFB_Encrypt';
function  SEA_OFB_Decrypt; external 'SEA_DLL' name 'SEA_OFB_Decrypt';

function  SEA_OMAC_Init;      external 'SEA_DLL' name 'SEA_OMAC_Init';
function  SEA_OMAC_Update;    external 'SEA_DLL' name 'SEA_OMAC_Update';
procedure SEA_OMAC_Final;     external 'SEA_DLL' name 'SEA_OMAC_Final';
procedure SEA_OMAC1_Final;    external 'SEA_DLL' name 'SEA_OMAC1_Final';
procedure SEA_OMAC2_Final;    external 'SEA_DLL' name 'SEA_OMAC2_Final';

function  SEA_EAX_Init;            external 'SEA_DLL' name 'SEA_EAX_Init';
function  SEA_EAX_Encrypt;         external 'SEA_DLL' name 'SEA_EAX_Encrypt';
function  SEA_EAX_Decrypt;         external 'SEA_DLL' name 'SEA_EAX_Decrypt';
procedure SEA_EAX_Final;           external 'SEA_DLL' name 'SEA_EAX_Final';
function  SEA_EAX_Provide_Header;  external 'SEA_DLL' name 'SEA_EAX_Provide_Header';


{$define CONST}
{$i sea_seek.inc}

end.
