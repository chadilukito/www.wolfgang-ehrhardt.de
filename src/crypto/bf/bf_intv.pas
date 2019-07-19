unit BF_INTV;


{$ifdef VirtualPascal}
  {$stdcall+}
{$else}
  Error('Interface unit for VirtualPascal');
{$endif}

(*************************************************************************

 DESCRIPTION     :  Interface unit for BF_DLL

 REQUIREMENTS    :  VirtualPascal

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     24.12.04  W.Ehrhardt  Initial version a la BF_INTF
 0.11     16.06.07  we          BF_Reset interfaced; BF_OMAC, BF_EAX
 0.12     11.07.09  we          BF_DLL_Version returns PAnsiChar
 0.13     05.08.10  we          Longint ILen, removed OMAC XL version
 0.14     05.08.10  we          BF_CTR_Seek/64 via bf_seek.inc
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2004-2010 Wolfgang Ehrhardt

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
  BF_Err_Invalid_Key_Size       = -1;  {Key size in bytes <1 or >56}
  BF_Err_Invalid_Length         = -3;  {No full block for cipher stealing}
  BF_Err_Data_After_Short_Block = -4;  {Short block must be last}
  BF_Err_MultipleIncProcs       = -5;  {More than one IncProc Setting}
  BF_Err_NIL_Pointer            = -6;  {nil pointer to block with nonzero length}

  BF_Err_CTR_SeekOffset         = -15; {Invalid offset in BF_CTR_Seek}
  BF_Err_Invalid_16Bit_Length   = -20; {Pointer + Offset > $FFFF for 16 bit code}

type
  TBFParray  = packed array[0..17]  of longint;
  TBFSBox    = packed array[0..255] of longint;
  TBFSBoxArr = packed array[0..3]   of TBFSbox;
  TBFBlock   = packed array[0..7]   of byte;
  PBFBlock   = ^TBFBlock;

type
  TBFIncProc = procedure(var CTR: TBFBlock);   {user supplied IncCTR proc}
                {$ifdef DLL} stdcall; {$endif}
type
  TBFContext = packed record
                 SBox    : TBFSboxArr; {key dependend SBox     }
                 PArray  : TBFPArray;  {key dependend PArray   }
                 IV      : TBFBlock;   {IV or CTR              }
                 buf     : TBFBlock;   {Work buffer            }
                 bLen    : word;       {Bytes used in buf      }
                 Flag    : word;       {Bit 1: Short block     }
                 IncProc : TBFIncProc; {Increment proc CTR-Mode}
               end;

const
  BFBLKSIZE  = sizeof(TBFBlock);

type
  TBF_EAXContext = packed record
                      HdrOMAC : TBFContext; {Hdr OMAC1  context}
                      MsgOMAC : TBFContext; {Msg OMAC1  context}
                      ctr_ctx : TBFContext; {Msg BFCTR context }
                      NonceTag: TBFBlock;   {nonce tag         }
                      tagsize : word;       {tag size (unused) }
                      flags   : word;       {ctx flags (unused)}
                    end;


function  BF_DLL_Version: PAnsiChar;
  {-Return DLL version as PAnsiChar}



function  BF_Init(const Key; KeyBytes: word; var ctx: TBFContext): integer;
  {-Blowfish PArray and SBox initialisation}

procedure BF_Encrypt(var ctx: TBFContext; const BI: TBFBlock; var BO: TBFBlock);
  {-encrypt one block (in ECB mode)}

procedure BF_Decrypt(var ctx: TBFContext; const BI: TBFBlock; var BO: TBFBlock);
  {-decrypt one block (in ECB mode)}

procedure BF_XorBlock(const B1, B2: TBFBlock; var B3: TBFBlock);
  {-xor two blocks, result in third}

procedure BF_Reset(var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag}

procedure BF_SetFastInit(value: boolean);
  {-set FastInit variable}

function  BF_GetFastInit: boolean;
  {-Returns FastInit variable}



function  BF_CBC_Init(const Key; KeyBytes: word; const IV: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size, save IV}

procedure BF_CBC_Reset(const IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, save IV}

function  BF_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  BF_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  BF_CFB_Init(const Key; KeyBytes: word; const IV: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size, encrypt IV}

procedure BF_CFB_Reset(const IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  BF_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB128 mode}

function  BF_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB128 mode}



function  BF_CTR_Init(const Key; KeyBytes: word; const CTR: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if inv. key size, encrypt CTR}

procedure BF_CTR_Reset(const CTR: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}

function  BF_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  BF_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  BF_CTR_Seek(const iCTR: TBFBlock; SOL, SOH: longint; var ctx: TBFContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in BF_CTR_Init.}

function  BF_SetIncProc(IncP: TBFIncProc; var ctx: TBFContext): integer;
  {-Set user supplied IncCTR proc}

procedure BF_IncMSBFull(var CTR: TBFBlock);
  {-Increment CTR[7]..CTR[0]}

procedure BF_IncLSBFull(var CTR: TBFBlock);
  {-Increment CTR[0]..CTR[7]}

procedure BF_IncMSBPart(var CTR: TBFBlock);
  {-Increment CTR[7]..CTR[4]}

procedure BF_IncLSBPart(var CTR: TBFBlock);
  {-Increment CTR[0]..CTR[3]}



function  BF_ECB_Init(const Key; KeyBytes: word; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size}

procedure BF_ECB_Reset(var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag}

function  BF_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  BF_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  BF_OFB_Init(const Key; KeyBytes: word; const IV: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size, encrypt IV}

procedure BF_OFB_Reset(const IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  BF_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  BF_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}



function  BF_OMAC_Init(const Key; KeyBytes: word; var ctx: TBFContext): integer;
  {-OMAC init: BF key expansion, error if inv. key size}

function  BF_OMAC_Update(data: pointer; ILen: longint; var ctx: TBFContext): integer;
  {-OMAC data input, may be called more than once}

procedure BF_OMAC_Final(var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC=OMAC1 tag}

procedure BF_OMAC1_Final(var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC1 tag}

procedure BF_OMAC2_Final(var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC2 tag}



function BF_EAX_Init(const Key; KeyBytes: word; const nonce; nLen: word; var ctx: TBF_EAXContext): integer;
  {-Init hdr and msg OMACs, setup BFCTR with nonce tag}

function BF_EAX_Provide_Header(Hdr: pointer; hLen: word; var ctx: TBF_EAXContext): integer;
  {-Supply a message header. The header "grows" with each call}

function BF_EAX_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBF_EAXContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

function BF_EAX_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBF_EAXContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

procedure BF_EAX_Final(var tag: TBFBlock; var ctx: TBF_EAXContext);
  {-Compute EAX tag from context}



implementation



function  BF_DLL_Version; external 'BF_DLL' name 'BF_DLL_Version';

function  BF_Init;        external 'BF_DLL' name 'BF_Init';
procedure BF_Encrypt;     external 'BF_DLL' name 'BF_Encrypt';
procedure BF_Decrypt;     external 'BF_DLL' name 'BF_Decrypt';
procedure BF_XorBlock;    external 'BF_DLL' name 'BF_XorBlock';
procedure BF_Reset;       external 'BF_DLL' name 'BF_Reset';
procedure BF_SetFastInit; external 'BF_DLL' name 'BF_SetFastInit';
function  BF_GetFastInit; external 'BF_DLL' name 'BF_GetFastInit';

function  BF_CBC_Init;    external 'BF_DLL' name 'BF_CBC_Init';
procedure BF_CBC_Reset;   external 'BF_DLL' name 'BF_CBC_Reset';
function  BF_CBC_Encrypt; external 'BF_DLL' name 'BF_CBC_Encrypt';
function  BF_CBC_Decrypt; external 'BF_DLL' name 'BF_CBC_Decrypt';

function  BF_CFB_Init;    external 'BF_DLL' name 'BF_CFB_Init';
procedure BF_CFB_Reset;   external 'BF_DLL' name 'BF_CFB_Reset';
function  BF_CFB_Encrypt; external 'BF_DLL' name 'BF_CFB_Encrypt';
function  BF_CFB_Decrypt; external 'BF_DLL' name 'BF_CFB_Decrypt';

function  BF_CTR_Init;    external 'BF_DLL' name 'BF_CTR_Init';
procedure BF_CTR_Reset;   external 'BF_DLL' name 'BF_CTR_Reset';
function  BF_CTR_Encrypt; external 'BF_DLL' name 'BF_CTR_Encrypt';
function  BF_CTR_Decrypt; external 'BF_DLL' name 'BF_CTR_Decrypt';
function  BF_SetIncProc;  external 'BF_DLL' name 'BF_SetIncProc';
procedure BF_IncMSBFull;  external 'BF_DLL' name 'BF_IncMSBFull';
procedure BF_IncLSBFull;  external 'BF_DLL' name 'BF_IncLSBFull';
procedure BF_IncMSBPart;  external 'BF_DLL' name 'BF_IncMSBPart';
procedure BF_IncLSBPart;  external 'BF_DLL' name 'BF_IncLSBPart';

function  BF_ECB_Init;    external 'BF_DLL' name 'BF_ECB_Init';
procedure BF_ECB_Reset;   external 'BF_DLL' name 'BF_ECB_Reset';
function  BF_ECB_Encrypt; external 'BF_DLL' name 'BF_ECB_Encrypt';
function  BF_ECB_Decrypt; external 'BF_DLL' name 'BF_ECB_Decrypt';

function  BF_OFB_Init;    external 'BF_DLL' name 'BF_OFB_Init';
procedure BF_OFB_Reset;   external 'BF_DLL' name 'BF_OFB_Reset';
function  BF_OFB_Encrypt; external 'BF_DLL' name 'BF_OFB_Encrypt';
function  BF_OFB_Decrypt; external 'BF_DLL' name 'BF_OFB_Decrypt';

function  BF_OMAC_Init;      external 'BF_DLL' name 'BF_OMAC_Init';
function  BF_OMAC_Update;    external 'BF_DLL' name 'BF_OMAC_Update';
procedure BF_OMAC_Final;     external 'BF_DLL' name 'BF_OMAC_Final';
procedure BF_OMAC1_Final;    external 'BF_DLL' name 'BF_OMAC1_Final';
procedure BF_OMAC2_Final;    external 'BF_DLL' name 'BF_OMAC2_Final';

function  BF_EAX_Init;            external 'BF_DLL' name 'BF_EAX_Init';
function  BF_EAX_Encrypt;         external 'BF_DLL' name 'BF_EAX_Encrypt';
function  BF_EAX_Decrypt;         external 'BF_DLL' name 'BF_EAX_Decrypt';
procedure BF_EAX_Final;           external 'BF_DLL' name 'BF_EAX_Final';
function  BF_EAX_Provide_Header;  external 'BF_DLL' name 'BF_EAX_Provide_Header';

{$define CONST}
{$i bf_seek.inc}

end.
