library SEA_DLL;

{$ifndef DLL}
  error('compile with $define DLL');
  end.
{$endif}


(*************************************************************************

 DESCRIPTION     :  DLL for SEED Encryption Algorithm

 REQUIREMENTS    :  D2-D7/D9-D10/D12, compile with $define DLL

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REMARK          :  SEA_CTR_Seek64 will be supplied by interface unit

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     16.06.07  W.Ehrhardt  Initial version analog TF_DLL
 0.11     15.07.09  we          SEA_DLL_Version returns PAnsiChar
 0.12     26.07.10  we          Longint ILen, SEA_Err_Invalid_16Bit_Length
 0.13     27.07.10  we          Removed OMAC XL version
 0.14     28.07.10  we          SEA_CTR_Seek
 0.15     31.07.10  we          Removed SEA_CTR_Seek (handled in interface unit)
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

uses
  sea_base, sea_ctr, sea_cfb, sea_ofb, sea_cbc, sea_ecb, sea_omac, sea_eax;

{$R *.RES}

{---------------------------------------------------------------------------}
function SEA_DLL_Version: PAnsiChar; stdcall;
  {-Return DLL version as PAnsiChar}
begin
  Result := '0.15';
end;

exports  SEA_DLL_Version        name 'SEA_DLL_Version';
exports  SEA_XorBlock           name 'SEA_XorBlock';
exports  SEA_Init               name 'SEA_Init';
exports  SEA_Encrypt            name 'SEA_Encrypt';
exports  SEA_Decrypt            name 'SEA_Decrypt';
exports  SEA_Reset              name 'SEA_Reset';
exports  SEA_SetFastInit        name 'SEA_SetFastInit';
exports  SEA_GetFastInit        name 'SEA_GetFastInit';

exports  SEA_ECB_Init           name 'SEA_ECB_Init';
exports  SEA_ECB_Reset          name 'SEA_ECB_Reset';
exports  SEA_ECB_Encrypt        name 'SEA_ECB_Encrypt';
exports  SEA_ECB_Decrypt        name 'SEA_ECB_Decrypt';

exports  SEA_CBC_Init           name 'SEA_CBC_Init';
exports  SEA_CBC_Reset          name 'SEA_CBC_Reset';
exports  SEA_CBC_Encrypt        name 'SEA_CBC_Encrypt';
exports  SEA_CBC_Decrypt        name 'SEA_CBC_Decrypt';

exports  SEA_CFB_Init           name 'SEA_CFB_Init';
exports  SEA_CFB_Reset          name 'SEA_CFB_Reset';
exports  SEA_CFB_Encrypt        name 'SEA_CFB_Encrypt';
exports  SEA_CFB_Decrypt        name 'SEA_CFB_Decrypt';

exports  SEA_OFB_Init           name 'SEA_OFB_Init';
exports  SEA_OFB_Reset          name 'SEA_OFB_Reset';
exports  SEA_OFB_Encrypt        name 'SEA_OFB_Encrypt';
exports  SEA_OFB_Decrypt        name 'SEA_OFB_Decrypt';

exports  SEA_CTR_Init           name 'SEA_CTR_Init';
exports  SEA_CTR_Reset          name 'SEA_CTR_Reset';
exports  SEA_CTR_Encrypt        name 'SEA_CTR_Encrypt';
exports  SEA_CTR_Decrypt        name 'SEA_CTR_Decrypt';
exports  SEA_SetIncProc         name 'SEA_SetIncProc';
exports  SEA_IncMSBFull         name 'SEA_IncMSBFull';
exports  SEA_IncLSBFull         name 'SEA_IncLSBFull';
exports  SEA_IncMSBPart         name 'SEA_IncMSBPart';
exports  SEA_IncLSBPart         name 'SEA_IncLSBPart';

exports  SEA_OMAC_Init          name 'SEA_OMAC_Init';
exports  SEA_OMAC_Update        name 'SEA_OMAC_Update';
exports  SEA_OMAC_Final         name 'SEA_OMAC_Final';
exports  SEA_OMAC1_Final        name 'SEA_OMAC1_Final';
exports  SEA_OMAC2_Final        name 'SEA_OMAC2_Final';

exports  SEA_EAX_Init           name 'SEA_EAX_Init';
exports  SEA_EAX_Provide_Header name 'SEA_EAX_Provide_Header';
exports  SEA_EAX_Encrypt        name 'SEA_EAX_Encrypt';
exports  SEA_EAX_Decrypt        name 'SEA_EAX_Decrypt';
exports  SEA_EAX_Final          name 'SEA_EAX_Final';

end.

