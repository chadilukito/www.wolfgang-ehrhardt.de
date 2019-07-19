library BF_DLL;

{$ifndef DLL}
  error('compile with $define DLL');
  end.
{$endif}


(*************************************************************************

 DESCRIPTION     :  DLL for Blowfish

 REQUIREMENTS    :  D2-D7/D9-D10/D12, compile with $define DLL

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     24.12.04  W.Ehrhardt  Initial version analog AES.DLL
 0.11     24.12.04  we          BF_Get/SetFastInit
 0.12     16.06.07  we          BF_OMAC, BF_EAX; exports BF_Reset
 0.13     11.07.09  we          BF_DLL_Version returns PAnsiChar
 0.14     05.08.10  we          Longint ILen, removed OMAC XL version
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

uses
  bf_base, bf_ctr, bf_cfb, bf_ofb, bf_cbc, bf_ecb, bf_omac, bf_eax;

{$R *.RES}


function BF_DLL_Version: PAnsiChar; stdcall;
  {-Return DLL version as PAnsiChar}
begin
  Result := '0.14';
end;


exports  BF_DLL_Version        name 'BF_DLL_Version';
exports  BF_XorBlock           name 'BF_XorBlock';
exports  BF_Init               name 'BF_Init';
exports  BF_Encrypt            name 'BF_Encrypt';
exports  BF_Decrypt            name 'BF_Decrypt';
exports  BF_Reset              name 'BF_Reset';
exports  BF_SetFastInit        name 'BF_SetFastInit';
exports  BF_GetFastInit        name 'BF_GetFastInit';

exports  BF_ECB_Init           name 'BF_ECB_Init';
exports  BF_ECB_Reset          name 'BF_ECB_Reset';
exports  BF_ECB_Encrypt        name 'BF_ECB_Encrypt';
exports  BF_ECB_Decrypt        name 'BF_ECB_Decrypt';

exports  BF_CBC_Init           name 'BF_CBC_Init';
exports  BF_CBC_Reset          name 'BF_CBC_Reset';
exports  BF_CBC_Encrypt        name 'BF_CBC_Encrypt';
exports  BF_CBC_Decrypt        name 'BF_CBC_Decrypt';

exports  BF_CFB_Init           name 'BF_CFB_Init';
exports  BF_CFB_Reset          name 'BF_CFB_Reset';
exports  BF_CFB_Encrypt        name 'BF_CFB_Encrypt';
exports  BF_CFB_Decrypt        name 'BF_CFB_Decrypt';

exports  BF_OFB_Init           name 'BF_OFB_Init';
exports  BF_OFB_Reset          name 'BF_OFB_Reset';
exports  BF_OFB_Encrypt        name 'BF_OFB_Encrypt';
exports  BF_OFB_Decrypt        name 'BF_OFB_Decrypt';

exports  BF_CTR_Init           name 'BF_CTR_Init';
exports  BF_CTR_Reset          name 'BF_CTR_Reset';
exports  BF_CTR_Encrypt        name 'BF_CTR_Encrypt';
exports  BF_CTR_Decrypt        name 'BF_CTR_Decrypt';
exports  BF_SetIncProc         name 'BF_SetIncProc';
exports  BF_IncMSBFull         name 'BF_IncMSBFull';
exports  BF_IncLSBFull         name 'BF_IncLSBFull';
exports  BF_IncMSBPart         name 'BF_IncMSBPart';
exports  BF_IncLSBPart         name 'BF_IncLSBPart';

exports  BF_OMAC_Init          name 'BF_OMAC_Init';
exports  BF_OMAC_Update        name 'BF_OMAC_Update';
exports  BF_OMAC_Final         name 'BF_OMAC_Final';
exports  BF_OMAC1_Final        name 'BF_OMAC1_Final';
exports  BF_OMAC2_Final        name 'BF_OMAC2_Final';

exports  BF_EAX_Init           name 'BF_EAX_Init';
exports  BF_EAX_Provide_Header name 'BF_EAX_Provide_Header';
exports  BF_EAX_Encrypt        name 'BF_EAX_Encrypt';
exports  BF_EAX_Decrypt        name 'BF_EAX_Decrypt';
exports  BF_EAX_Final          name 'BF_EAX_Final';

end.


