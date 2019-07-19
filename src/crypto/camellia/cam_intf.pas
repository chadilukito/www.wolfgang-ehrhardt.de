unit CAM_INTF;

(*************************************************************************

 DESCRIPTION     :  Interface unit for CAM_DLL

 REQUIREMENTS    :  D2-D7/D9-D12/D17-D18/D25S, FPC

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     16.06.08  W.Ehrhardt  Initial version analog TF_INTF
 0.11     17.06.08  we          CAM_CPRF128
 0.12     21.06.08  we          Fill word in ctx for align 8
 0.13     21.05.09  we          All-in-one functions CAM_EAX_Enc_Auth/CAM_EAX_Dec_Veri
 0.14     21.05.09  we          CAM_CCM
 0.15     13.07.09  we          CAM_DLL_DLL_Version returns PAnsiChar, external 'CAM_DLL.DLL'
 0.16     28.07.10  we          CAM_CTR_Seek
 0.17     29.07.10  we          Longint ILen in CAM_xxx_En/Decrypt, CAM_OMAC_UpdateXL removed
 0.18     31.07.10  we          CAM_CTR_Seek via cam_seek.inc
 0.19     09.11.17  we          CAM_GCM
**************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2008-2017 Wolfgang Ehrhardt

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
  CAM_Err_Invalid_Key_Size       = -1;  {Key size in bits not 128, 192, or 256}
  CAM_Err_Invalid_Length         = -3;  {No full block for cipher stealing}
  CAM_Err_Data_After_Short_Block = -4;  {Short block must be last}
  CAM_Err_MultipleIncProcs       = -5;  {More than one IncProc Setting}
  CAM_Err_NIL_Pointer            = -6;  {nil pointer to block with nonzero length}

  CAM_Err_EAX_Inv_Text_Length    = -7;  {More than 64K text length in EAX all-in-one for 16 Bit}
  CAM_Err_EAX_Inv_TAG_Length     = -8;  {EAX all-in-one tag length not 0..16}
  CAM_Err_EAX_Verify_Tag         = -9;  {EAX all-in-one tag does not compare}

  CAM_Err_CCM_Hdr_length         = -10; {CCM header length >= $FF00}
  CAM_Err_CCM_Nonce_length       = -11; {CCM nonce length < 7 or > 13}
  CAM_Err_CCM_Tag_length         = -12; {CCM tag length not in [4,6,8,19,12,14,16]}
  CAM_Err_CCM_Verify_Tag         = -13; {Computed CCM tag does not compare}
  CAM_Err_CCM_Text_length        = -14; {16 bit plain/cipher text length to large}

  CAM_Err_CTR_SeekOffset         = -15; {Negative offset in CAM_CTR_Seek}
  CAM_Err_Invalid_16Bit_Length   = -20; {Pointer + Offset > $FFFF for 16 bit code}

type
  TCAMBlock  = packed array[0..15] of byte;      {128 bit block}
  TCAMRndKey = packed array[0..16] of TCAMBlock; {Round key schedule}
  PCAMBlock  = ^TCAMBlock;

type
  TCAMIncProc = procedure(var CTR: TCAMBlock);   {user supplied IncCTR proc}
                {$ifdef USEDLL} stdcall; {$endif}

type
  TCAMContext = packed record
                 IV      : TCAMBlock;   {IV or CTR              }
                 buf     : TCAMBlock;   {Work buffer            }
                 bLen    : word;        {Bytes used in buf      }
                 Flag    : word;        {Bit 1: Short block     }
                 KeyBits : word;        {Bit size of key        }
                 Fill    : word;        {Fill for Align 8       }
                 IncProc : TCAMIncProc; {Increment proc CTR-Mode}
                 EK      : TCAMRndKey;  {Extended round key     }
               end;
const
  CAMBLKSIZE  = sizeof(TCAMBlock);     {Camellia block size in bytes}

type
  TCAM_EAXContext = packed record
                      HdrOMAC : TCAMContext; {Hdr OMAC1  context}
                      MsgOMAC : TCAMContext; {Msg OMAC1  context}
                      ctr_ctx : TCAMContext; {Msg CAMCTR context}
                      NonceTag: TCAMBlock;   {nonce tag         }
                      tagsize : word;        {tag size (unused) }
                      flags   : word;        {ctx flags (unused)}
                    end;

type
  TCAMGCM_Tab4K = array[0..255] of TCAMBlock;  {64 KB gf_mul_h table  }

type
  TBit64 = packed array[0..1] of longint;      {64 bit counter        }

type
  TCAM_GCMContext = packed record
                      actx    : TCAMContext;   {Basic CAM context     }
                      aad_ghv : TCAMBlock;     {ghash value AAD       }
                      txt_ghv : TCAMBlock;     {ghash value ciphertext}
                      ghash_h : TCAMBlock;     {ghash H value         }
                      gf_t4k  : TCAMGCM_Tab4K; {gf_mul_h table        }
                      aad_cnt : TBit64;        {processed AAD bytes   }
                      atx_cnt : TBit64;        {authent. text bytes   }
                      y0_val  : longint;       {initial 32-bit ctr val}
                    end;


function  CAM_DLL_Version: PAnsiChar;
stdcall; external 'CAM_DLL.DLL' name 'CAM_DLL_Version';
  {-Return DLL version as PAnsiChar}


function  CAM_Init(const Key; KeyBits: word; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_Init';
  {-Camellia context/round key initialization}

procedure CAM_Encrypt(var ctx: TCAMContext; const BI: TCAMBlock; var BO: TCAMBlock);
stdcall; external 'CAM_DLL.DLL' name 'CAM_Encrypt';
  {-encrypt one block (in ECB mode)}

procedure CAM_Decrypt(var ctx: TCAMContext; const BI: TCAMBlock; var BO: TCAMBlock);
stdcall; external 'CAM_DLL.DLL' name 'CAM_Decrypt';
  {-decrypt one block (in ECB mode)}

procedure CAM_XorBlock(const B1, B2: TCAMBlock; var B3: TCAMBlock);
stdcall; external 'CAM_DLL.DLL' name 'CAM_XorBlock';
  {-xor two blocks, result in third}

procedure CAM_Reset(var ctx: TCAMContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_Reset';
  {-Clears ctx fields bLen and Flag}

procedure CAM_SetFastInit(value: boolean);
stdcall; external 'CAM_DLL.DLL' name 'CAM_SetFastInit';
  {-set FastInit variable}

function  CAM_GetFastInit: boolean;
stdcall; external 'CAM_DLL.DLL' name 'CAM_GetFastInit';
  {-Returns FastInit variable}



function  CAM_CBC_Init(const Key; KeyBits: word; const IV: TCAMBlock; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_CBC_Init';
  {-Camellia key expansion, error if invalid key size, save IV}

procedure CAM_CBC_Reset(const IV: TCAMBlock; var ctx: TCAMContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_CBC_Reset';
  {-Clears ctx fields bLen and Flag, save IV}

function  CAM_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_CBC_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  CAM_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_CBC_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  CAM_CFB_Init(const Key; KeyBits: word; const IV: TCAMBlock; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_CFB_Init';
  {-Camellia key expansion, error if invalid key size, encrypt IV}

procedure CAM_CFB_Reset(const IV: TCAMBlock; var ctx: TCAMContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_CFB_Reset';
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  CAM_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_CFB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB128 mode}

function  CAM_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_CFB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB128 mode}



function  CAM_CTR_Init(const Key; KeyBits: word; const CTR: TCAMBlock; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_CTR_Init';
  {-Camellia key expansion, error if inv. key size, encrypt CTR}

procedure CAM_CTR_Reset(const CTR: TCAMBlock; var ctx: TCAMContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_CTR_Reset';
  {-Clears ctx fields bLen and Flag, encrypt CTR}

function  CAM_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_CTR_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  CAM_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_CTR_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  CAM_CTR_Seek(const iCTR: TCAMBlock; SOL, SOH: longint; var ctx: TCAMContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in CAM_CTR_Init.}

{$ifdef HAS_INT64}
function CAM_CTR_Seek64(const iCTR: TCAMBlock; SO: int64; var ctx: TCAMContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SO >= 0;}
  { iCTR is the initial CTR value for offset 0, i.e. the same as in CAM_CTR_Init.}
{$endif}

function  CAM_SetIncProc(IncP: TCAMIncProc; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_SetIncProc';
  {-Set user supplied IncCTR proc}

procedure CAM_IncMSBFull(var CTR: TCAMBlock);
stdcall; external 'CAM_DLL.DLL' name 'CAM_IncMSBFull';
  {-Increment CTR[15]..CTR[0]}

procedure CAM_IncLSBFull(var CTR: TCAMBlock);
stdcall; external 'CAM_DLL.DLL' name 'CAM_IncLSBFull';
  {-Increment CTR[0]..CTR[15]}

procedure CAM_IncMSBPart(var CTR: TCAMBlock);
stdcall; external 'CAM_DLL.DLL' name 'CAM_IncMSBPart';
  {-Increment CTR[15]..CTR[8]}

procedure CAM_IncLSBPart(var CTR: TCAMBlock);
stdcall; external 'CAM_DLL.DLL' name 'CAM_IncLSBPart';
  {-Increment CTR[0]..CTR[7]}



function  CAM_ECB_Init(const Key; KeyBits: word; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_ECB_Init';
  {-Camellia key expansion, error if invalid key size}

procedure CAM_ECB_Reset(var ctx: TCAMContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_ECB_Reset';
  {-Clears ctx fields bLen and Flag}

function  CAM_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_ECB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  CAM_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_ECB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  CAM_OFB_Init(const Key; KeyBits: word; const IV: TCAMBlock; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_OFB_Init';
  {-Camellia key expansion, error if invalid key size, encrypt IV}

procedure CAM_OFB_Reset(const IV: TCAMBlock; var ctx: TCAMContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_OFB_Reset';
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  CAM_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_OFB_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  CAM_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_OFB_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}



function  CAM_OMAC_Init(const Key; KeyBits: word; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_OMAC_Init';
  {-OMAC init: Camellia key expansion, error if inv. key size}

function  CAM_OMAC_Update(data: pointer; ILen: longint; var ctx: TCAMContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_OMAC_Update';
  {-OMAC data input, may be called more than once}

procedure CAM_OMAC_Final(var tag: TCAMBlock; var ctx: TCAMContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_OMAC_Final';
  {-end data input, calculate OMAC=OMAC1 tag}

procedure CAM_OMAC1_Final(var tag: TCAMBlock; var ctx: TCAMContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_OMAC1_Final';
  {-end data input, calculate OMAC1 tag}

procedure CAM_OMAC2_Final(var tag: TCAMBlock; var ctx: TCAMContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_OMAC2_Final';
  {-end data input, calculate OMAC2 tag}



function CAM_EAX_Init(const Key; KBits: word; const nonce; nLen: word; var ctx: TCAM_EAXContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_EAX_Init';
  {-Init hdr and msg OMACs, setp CAMCTR with nonce tag}

function CAM_EAX_Provide_Header(Hdr: pointer; hLen: word; var ctx: TCAM_EAXContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_EAX_Provide_Header';
  {-Supply a message header. The header "grows" with each call}

function CAM_EAX_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAM_EAXContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_EAX_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

function CAM_EAX_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAM_EAXContext): integer;
stdcall; external 'CAM_DLL.DLL' name 'CAM_EAX_Decrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

procedure CAM_EAX_Final(var tag: TCAMBlock; var ctx: TCAM_EAXContext);
stdcall; external 'CAM_DLL.DLL' name 'CAM_EAX_Final';
  {-Compute EAX tag from context}

function  CAM_EAX_Enc_Auth(var tag: TCAMBlock;               {Tag record}
                         const Key; KBits: word;             {key and bitlength of key}
                       const nonce; nLen: word;              {nonce: address / length}
                               Hdr: pointer; hLen: word;     {header: address / length}
                               ptp: pointer; pLen: longint;  {plaintext: address / length}
                               ctp: pointer                  {ciphertext: address}
                                 ): integer;
stdcall;  external 'CAM_DLL.DLL' name 'CAM_EAX_Enc_Auth';
  {-All-in-one call to encrypt/authenticate}

function  CAM_EAX_Dec_Veri(   ptag: pointer; tLen : word;    {Tag: address / length (0..16)}
                         const Key; KBits: word;             {key and bitlength of key}
                       const nonce; nLen : word;             {nonce: address / length}
                               Hdr: pointer; hLen: word;     {header: address / length}
                               ctp: pointer; cLen: longint;  {ciphertext: address / length}
                               ptp: pointer                  {plaintext: address}
                                 ): integer;
stdcall;  external 'CAM_DLL.DLL' name 'CAM_EAX_Dec_Veri';
  {-All-in-one call to decrypt/verify. Decryption is done only if ptag^ is verified}



function CAM_CPRF128(const Key; KeyBytes: word; msg: pointer; msglen: longint; var PRV: TCAMBlock): integer;
stdcall;  external 'CAM_DLL.DLL' name 'CAM_CPRF128';
  {-Calculate variable-length key Camellia CMAC Pseudo-Random Function-128 for msg}
  { returns CAM_OMAC error and 128-bit pseudo-random value PRV}

function CAM_CPRF128_selftest: boolean;
stdcall;  external 'CAM_DLL.DLL' name 'CAM_CPRF128_selftest';
  {-Selftest with ipsec-camellia-cmac96and128 test vectors}



function CAM_CCM_Enc_AuthEx(var ctx: TCAMContext;
                            var tag: TCAMBlock; tLen : word;  {Tag & length in [4,6,8,19,12,14,16]}
                          const nonce;        nLen: word;     {nonce: address / length}
                                hdr: pointer; hLen: word;     {header: address / length}
                                ptp: pointer; pLen: longint;  {plaintext: address / length}
                                ctp: pointer                  {ciphertext: address}
                                  ): integer;
stdcall;  external 'CAM_DLL.DLL' name 'CAM_CCM_Enc_AuthEx';
  {-CCM packet encrypt/authenticate without key setup}


function CAM_CCM_Enc_Auth(var tag: TCAMBlock; tLen : word;  {Tag & length in [4,6,8,19,12,14,16]}
                      const   Key; KBytes: word;            {key and byte length of key}
                      const nonce; nLen: word;              {nonce: address / length}
                              hdr: pointer; hLen: word;     {header: address / length}
                              ptp: pointer; pLen: longint;  {plaintext: address / length}
                              ctp: pointer                  {ciphertext: address}
                                ): integer;
stdcall;  external 'CAM_DLL.DLL' name 'CAM_CCM_Enc_Auth';
  {-All-in-one call for CCM packet encrypt/authenticate}


function CAM_CCM_Dec_VeriEX(var ctx: TCAMContext;
                               ptag: pointer; tLen : word;    {Tag & length in [4,6,8,19,12,14,16]}
                        const nonce; nLen: word;              {nonce: address / length}
                                hdr: pointer; hLen: word;     {header: address / length}
                                ctp: pointer; cLen: longint;  {ciphertext: address / length}
                                ptp: pointer                  {plaintext: address}
                                  ): integer;
stdcall;  external 'CAM_DLL.DLL' name 'CAM_CCM_Dec_VeriEX';
  {-CCM packet decrypt/verify without key setup. If ptag^ verification fails, ptp^ is zero-filled!}


function CAM_CCM_Dec_Veri(   ptag: pointer; tLen : word;    {Tag & length in [4,6,8,19,12,14,16]}
                      const   Key; KBytes: word;            {key and byte length of key}
                      const nonce; nLen: word;              {nonce: address / length}
                              hdr: pointer; hLen: word;     {header: address / length}
                              ctp: pointer; cLen: longint;  {ciphertext: address / length}
                              ptp: pointer                  {plaintext: address}
                                ): integer;
stdcall;  external 'CAM_DLL.DLL' name 'CAM_CCM_Dec_Veri';
  {-All-in-one CCM packet decrypt/verify. If ptag^ verification fails, ptp^ is zero-filled!}



function CAM_GCM_Init(const Key; KeyBits: word; var ctx: TCAM_GCMContext): integer;
  {-Init context, calculate key-dependent GF(2^128) element H=E(K,0) and mul tables}
stdcall;  external 'cam_dll.dll' name 'CAM_GCM_Init';

function CAM_GCM_Reset_IV(pIV: pointer; IV_len: word; var ctx: TCAM_GCMContext): integer;
stdcall;  external 'cam_dll.dll' name 'CAM_GCM_Reset_IV';
  {-Reset: keep key but start new encryption with given IV}

function CAM_GCM_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAM_GCMContext): integer;
stdcall;  external 'cam_dll.dll' name 'CAM_GCM_Encrypt';
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update auth data}

function CAM_GCM_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAM_GCMContext): integer;
stdcall;  external 'cam_dll.dll' name 'CAM_GCM_Decrypt';
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode, update auth data}

function CAM_GCM_Add_AAD(pAAD: pointer; aLen: longint; var ctx: TCAM_GCMContext): integer;
stdcall;  external 'cam_dll.dll' name 'CAM_GCM_Add_AAD';
  {-Add additional authenticated data (will not be encrypted)}

function CAM_GCM_Final(var tag: TCAMBlock; var ctx: TCAM_GCMContext): integer;
stdcall;  external 'cam_dll.dll' name 'CAM_GCM_Final';
  {-Compute GCM tag from context}

function CAM_GCM_Enc_Auth(var tag: TCAMBlock;                     {Tag record}
                        const Key; KBits: word;                   {key and bitlength of key}
                              pIV: pointer; IV_len: word;         {IV: address / length}
                             pAAD: pointer; aLen: word;           {AAD: address / length}
                              ptp: pointer; pLen: longint;        {plaintext: address / length}
                              ctp: pointer;                       {ciphertext: address}
                          var ctx: TCAM_GCMContext                {context, will be cleared}
                                ): integer;
stdcall;  external 'cam_dll.dll' name 'CAM_GCM_Enc_Auth';
  {-All-in-one call to encrypt/authenticate}

function CAM_GCM_Dec_Veri(   ptag: pointer; tLen: word;           {Tag: address / length (0..16)}
                        const Key; KBits: word;                   {key and bitlength of key}
                              pIV: pointer; IV_len: word;         {IV: address / length}
                             pAAD: pointer; aLen: word;           {AAD: address / length}
                              ctp: pointer; cLen: longint;        {ciphertext: address / length}
                              ptp: pointer;                       {plaintext: address}
                          var ctx: TCAM_GCMContext                {context, will be cleared}
                                ): integer;
stdcall;  external 'cam_dll.dll' name 'CAM_GCM_Dec_Veri';
  {-All-in-one call to decrypt/verify. Decryption is done only if ptag^ is verified}


implementation

{$i cam_seek.inc}

end.
