unit ANU_INTV;

{$ifdef VirtualPascal}
  {$stdcall+}
{$else}
  Error('Interface unit for VirtualPascal');
{$endif}

(*************************************************************************

 DESCRIPTION     :  Interface unit for ANU_DLL

 REQUIREMENTS    :  VirtualPascal

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     08.08.08  W.Ehrhardt  Initial version
 0.11     16.08.08  we          Removed ANU_Reset
 0.12     13.07.09  we          ANU_DLL_Version returns PAnsiChar
 0.13     01.08.10  we          Longint ILen in ANU_xxx_En/Decrypt, ANU_OMAC_UpdateXL removed
 0.14     02.08.10  we          ANU_CTR_Seek, ANU_CTR_Seek64 via anu_seek.inc
**************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2008-2010 Wolfgang Ehrhardt

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
  ANU_Err_Invalid_Key_Size       = -1;  {Key size in bits not 128, 192, or 256}
  ANU_Err_Invalid_Mode           = -2;  {Encr/Decr with Init for Decr/Encr}
  ANU_Err_Invalid_Length         = -3;  {No full block for cipher stealing}
  ANU_Err_Data_After_Short_Block = -4;  {Short block must be last}
  ANU_Err_MultipleIncProcs       = -5;  {More than one IncProc Setting}
  ANU_Err_NIL_Pointer            = -6;  {nil pointer to block with nonzero length}
  ANU_Err_EAX_Inv_Text_Length    = -7;  {More than 64K text length in EAX all-in-one for 16 Bit}
  ANU_Err_EAX_Inv_TAG_Length     = -8;  {EAX all-in-one tag length not 0..16}
  ANU_Err_EAX_Verify_Tag         = -9;  {EAX all-in-one tag does not compare}
  ANU_Err_CTR_SeekOffset         = -15; {Negative offset in ANU_CTR_Seek}
  ANU_Err_Invalid_16Bit_Length   = -20; {Pointer + Offset > $FFFF for 16 bit code}

type
  TANURndKey = packed array[0..18,0..3] of longint;  {Round key schedule}
  TANUBlock  = packed array[0..15]  of byte;         {128 bit block}
  PANUBlock  = ^TANUBlock;

type
  TANUIncProc = procedure(var CTR: TANUBlock);   {user supplied IncCTR proc}
                   {$ifdef DLL} stdcall; {$endif}
type
  TANUContext = packed record
                 IV      : TANUBlock;   {IV or CTR              }
                 buf     : TANUBlock;   {Work buffer            }
                 bLen    : word;        {Bytes used in buf      }
                 Rounds  : word;        {Number of rounds       }
                 KeyBits : word;        {Number of bits in key  }
                 Decrypt : byte;        {<>0 if decrypting key  }
                 Flag    : byte;        {Bit 1: Short block     }
                 IncProc : TANUIncProc; {Increment proc CTR-Mode}
                 RK      : TANURndKey;  {Encr/Decr round keys   }
               end;

const
  ANUBLKSIZE  = sizeof(TANUBlock);     {Anubis block size in bytes}


type
  TANU_EAXContext = packed record
                      HdrOMAC : TANUContext; {Hdr OMAC1  context}
                      MsgOMAC : TANUContext; {Msg OMAC1  context}
                      ctr_ctx : TANUContext; {Msg ANUCTR context}
                      NonceTag: TANUBlock;   {nonce tag         }
                      tagsize : word;        {tag size (unused) }
                      flags   : word;        {ctx flags (unused)}
                    end;



function  ANU_DLL_Version: PAnsiChar;
  {-Return DLL version as PAnsiChar}



function  ANU_Init2(const Key; KeyBits: word; var ctx: TANUContext; decr: byte): integer;
  {-Anubis context/round key initialization, Inverse key if decr<>0}

function  ANU_Init_Encr(const Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis context/round key initialization for encrytion}

function  ANU_Init_Decr(const Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis context/round key initialization for decr<ptionn}

procedure ANU_Encrypt(var ctx: TANUContext; const BI: TANUBlock; var BO: TANUBlock);
  {-encrypt one block (in ECB mode)}

procedure ANU_Decrypt(var ctx: TANUContext; const BI: TANUBlock; var BO: TANUBlock);
  {-decrypt one block (in ECB mode)}

procedure ANU_XorBlock(const B1, B2: TANUBlock; var B3: TANUBlock);
  {-xor two blocks, result in third}


procedure ANU_SetFastInit(value: boolean);
  {-set FastInit variable}

function  ANU_GetFastInit: boolean;
  {-Returns FastInit variable}



function  ANU_ECB_Init_Encr(const Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis key expansion, error if invalid key size, encrypt IV}

function  ANU_ECB_Init_Decr(const Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis key expansion, error if invalid key size, encrypt IV}

function  ANU_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  ANU_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  ANU_CBC_Init_Encr(const Key; KeyBits: word; const IV: TANUBlock; var ctx: TANUContext): integer;
  {-Anubis key expansion, error if invalid key size, encrypt IV}

function  ANU_CBC_Init_Decr(const Key; KeyBits: word; const IV: TANUBlock; var ctx: TANUContext): integer;
  {-Anubis key expansion, error if invalid key size, encrypt IV}

function  ANU_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  ANU_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  ANU_CFB_Init(const Key; KeyBits: word; const IV: TANUBlock; var ctx: TANUContext): integer;
  {-Anubis key expansion, error if invalid key size, encrypt IV}

function  ANU_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB128 mode}

function  ANU_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB128 mode}



function  ANU_OFB_Init(const Key; KeyBits: word; const IV: TANUBlock; var ctx: TANUContext): integer;
  {-Anubis key expansion, error if invalid key size, encrypt IV}

function  ANU_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  ANU_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}



function  ANU_CTR_Init(const Key; KeyBits: word; const CTR: TANUBlock; var ctx: TANUContext): integer;
  {-Anubis key expansion, error if inv. key size, encrypt CTR}

function  ANU_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  ANU_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TANUContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  ANU_CTR_Seek(const iCTR: TANUBlock; SOL, SOH: longint; var ctx: TANUContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}

function  ANU_SetIncProc(IncP: TANUIncProc; var ctx: TANUContext): integer;
  {-Set user supplied IncCTR proc}

procedure ANU_IncMSBFull(var CTR: TANUBlock);
  {-Increment CTR[15]..CTR[0]}

procedure ANU_IncLSBFull(var CTR: TANUBlock);
  {-Increment CTR[0]..CTR[15]}

procedure ANU_IncMSBPart(var CTR: TANUBlock);
  {-Increment CTR[15]..CTR[8]}

procedure ANU_IncLSBPart(var CTR: TANUBlock);
  {-Increment CTR[0]..CTR[7]}



function  ANU_OMAC_Init(const Key; KeyBits: word; var ctx: TANUContext): integer;
  {-OMAC init: Anubis key expansion, error if inv. key size}

function  ANU_OMAC_Update(data: pointer; ILen: longint; var ctx: TANUContext): integer;
  {-OMAC data input, may be called more than once}

procedure ANU_OMAC_Final(var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC=OMAC1 tag}

procedure ANU_OMAC1_Final(var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC1 tag}

procedure ANU_OMAC2_Final(var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC2 tag}

procedure ANU_OMACx_Final(OMAC2: boolean; var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC tag}



function  ANU_EAX_Init(const Key; KBits: word; const nonce; nLen: word; var ctx: TANU_EAXContext): integer;
  {-Init hdr and msg OMACs, setp ANUCTR with nonce tag}

function  ANU_EAX_Provide_Header(Hdr: pointer; hLen: word; var ctx: TANU_EAXContext): integer;
  {-Supply a message header. The header "grows" with each call}

function  ANU_EAX_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TANU_EAXContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

function  ANU_EAX_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TANU_EAXContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

procedure ANU_EAX_Final(var tag: TANUBlock; var ctx: TANU_EAXContext);
  {-Compute EAX tag from context}

function  ANU_EAX_Enc_Auth(var tag: TANUBlock;               {Tag record}
                         const Key; KBits: word;             {key and bitlength of key}
                       const nonce; nLen: word;              {nonce: address / length}
                               Hdr: pointer; hLen: word;     {header: address / length}
                               ptp: pointer; pLen: longint;  {plaintext: address / length}
                               ctp: pointer                  {ciphertext: address}
                                 ): integer;
  {-All-in-one call to encrypt/authenticate}

function  ANU_EAX_Dec_Veri(   ptag: pointer; tLen : word;    {Tag: address / length (0..16)}
                         const Key; KBits: word;             {key and bitlength of key}
                       const nonce; nLen : word;             {nonce: address / length}
                               Hdr: pointer; hLen: word;     {header: address / length}
                               ctp: pointer; cLen: longint;  {ciphertext: address / length}
                               ptp: pointer                  {plaintext: address}
                                 ): integer;
  {-All-in-one call to decrypt/verify. Decryption is done only if ptag^ is verified}




implementation



function  ANU_DLL_Version;         external 'ANU_DLL' name 'ANU_DLL_Version';

procedure ANU_XorBlock;            external 'ANU_DLL' name 'ANU_XorBlock';
function  ANU_Init2;               external 'ANU_DLL' name 'ANU_Init2';
function  ANU_Init_Decr;           external 'ANU_DLL' name 'ANU_Init_Decr';
function  ANU_Init_Encr;           external 'ANU_DLL' name 'ANU_Init_Encr';
procedure ANU_Decrypt;             external 'ANU_DLL' name 'ANU_Decrypt';
procedure ANU_Encrypt;             external 'ANU_DLL' name 'ANU_Encrypt';
procedure ANU_SetFastInit;         external 'ANU_DLL' name 'ANU_SetFastInit';
function  ANU_GetFastInit;         external 'ANU_DLL' name 'ANU_GetFastInit';

function  ANU_ECB_Init_Encr;       external 'ANU_DLL' name 'ANU_ECB_Init_Encr';
function  ANU_ECB_Init_Decr;       external 'ANU_DLL' name 'ANU_ECB_Init_Decr';
function  ANU_ECB_Encrypt;         external 'ANU_DLL' name 'ANU_ECB_Encrypt';
function  ANU_ECB_Decrypt;         external 'ANU_DLL' name 'ANU_ECB_Decrypt';

function  ANU_CBC_Init_Encr;       external 'ANU_DLL' name 'ANU_CBC_Init_Encr';
function  ANU_CBC_Init_Decr;       external 'ANU_DLL' name 'ANU_CBC_Init_Decr';
function  ANU_CBC_Encrypt;         external 'ANU_DLL' name 'ANU_CBC_Encrypt';
function  ANU_CBC_Decrypt;         external 'ANU_DLL' name 'ANU_CBC_Decrypt';

function  ANU_CFB_Init;            external 'ANU_DLL' name 'ANU_CFB_Init';
function  ANU_CFB_Encrypt;         external 'ANU_DLL' name 'ANU_CFB_Encrypt';
function  ANU_CFB_Decrypt;         external 'ANU_DLL' name 'ANU_CFB_Decrypt';

function  ANU_CTR_Init;            external 'ANU_DLL' name 'ANU_CTR_Init';
function  ANU_CTR_Encrypt;         external 'ANU_DLL' name 'ANU_CTR_Encrypt';
function  ANU_CTR_Decrypt;         external 'ANU_DLL' name 'ANU_CTR_Decrypt';
function  ANU_SetIncProc;          external 'ANU_DLL' name 'ANU_SetIncProc';
procedure ANU_IncLSBFull;          external 'ANU_DLL' name 'ANU_IncLSBFull';
procedure ANU_IncLSBPart;          external 'ANU_DLL' name 'ANU_IncLSBPart';
procedure ANU_IncMSBFull;          external 'ANU_DLL' name 'ANU_IncMSBFull';
procedure ANU_IncMSBPart;          external 'ANU_DLL' name 'ANU_IncMSBPart';

function  ANU_OFB_Init;            external 'ANU_DLL' name 'ANU_OFB_Init';
function  ANU_OFB_Encrypt;         external 'ANU_DLL' name 'ANU_OFB_Encrypt';
function  ANU_OFB_Decrypt;         external 'ANU_DLL' name 'ANU_OFB_Decrypt';

function  ANU_OMAC_Init;           external 'ANU_DLL' name 'ANU_OMAC_Init';
function  ANU_OMAC_Update;         external 'ANU_DLL' name 'ANU_OMAC_Update';
procedure ANU_OMAC_Final;          external 'ANU_DLL' name 'ANU_OMAC_Final';
procedure ANU_OMAC1_Final;         external 'ANU_DLL' name 'ANU_OMAC1_Final';
procedure ANU_OMAC2_Final;         external 'ANU_DLL' name 'ANU_OMAC2_Final';
procedure ANU_OMACx_Final;         external 'ANU_DLL' name 'ANU_OMACx_Final';

function  ANU_EAX_Init;            external 'ANU_DLL' name 'ANU_EAX_Init';
function  ANU_EAX_Encrypt;         external 'ANU_DLL' name 'ANU_EAX_Encrypt';
function  ANU_EAX_Decrypt;         external 'ANU_DLL' name 'ANU_EAX_Decrypt';
procedure ANU_EAX_Final;           external 'ANU_DLL' name 'ANU_EAX_Final';
function  ANU_EAX_Provide_Header;  external 'ANU_DLL' name 'ANU_EAX_Provide_Header';
function  ANU_EAX_Enc_Auth;        external 'ANU_DLL' name 'ANU_EAX_Enc_Auth';
function  ANU_EAX_Dec_Veri;        external 'ANU_DLL' name 'ANU_EAX_Dec_Veri';

{$define CONST}
{$i anu_seek.inc}

end.

