library CAM_DLL;

{$ifndef DLL}
  error('compile with $define DLL');
  end.
{$endif}


(*************************************************************************

 DESCRIPTION     :  DLL for Camellia Block Cipher

 REQUIREMENTS    :  D2-D7/D9-D12/D17-D18/D25S, compile with $define DLL

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     16.06.08  W.Ehrhardt  Initial version analog TF_DLL
 0.11     17.06.08  we          CAM_CPRF128
 0.12     05.09.08  we          New version number for 32 bit code
 0.13     21.05.09  we          All-in-one functions CAM_EAX_Enc_Auth/CAM_EAX_Dec_Veri
 0.14     21.05.09  we          CAM_CCM
 0.15     13.07.09  we          CAM_DLL_DLL_Version returns PAnsiChar
 0.16     28.07.10  we          CAM_CTR_Seek
 0.17     29.07.10  we          Longint ILen in CAM_xxx_En/Decrypt, CAM_OMAC_UpdateXL removed
 0.18     31.07.10  we          Removed CAM_CTR_Seek (handled in interface unit)
 0.19     08.11.17  we          GCM functions
***************************************************************************)

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

uses
  cam_base, cam_ctr, cam_cfb, cam_ofb, cam_cbc, cam_ecb,
  cam_omac, cam_eax, cam_cprf, cam_ccm, cam_gcm;

{$R *.RES}


{---------------------------------------------------------------------------}
function CAM_DLL_Version: PAnsiChar; stdcall;
  {-Return DLL version as PAnsiChar}
begin
  Result := '0.19';
end;


exports  CAM_DLL_Version        name 'CAM_DLL_Version';
exports  CAM_XorBlock           name 'CAM_XorBlock';
exports  CAM_Init               name 'CAM_Init';
exports  CAM_Encrypt            name 'CAM_Encrypt';
exports  CAM_Decrypt            name 'CAM_Decrypt';
exports  CAM_Reset              name 'CAM_Reset';
exports  CAM_SetFastInit        name 'CAM_SetFastInit';
exports  CAM_GetFastInit        name 'CAM_GetFastInit';

exports  CAM_ECB_Init           name 'CAM_ECB_Init';
exports  CAM_ECB_Reset          name 'CAM_ECB_Reset';
exports  CAM_ECB_Encrypt        name 'CAM_ECB_Encrypt';
exports  CAM_ECB_Decrypt        name 'CAM_ECB_Decrypt';

exports  CAM_CBC_Init           name 'CAM_CBC_Init';
exports  CAM_CBC_Reset          name 'CAM_CBC_Reset';
exports  CAM_CBC_Encrypt        name 'CAM_CBC_Encrypt';
exports  CAM_CBC_Decrypt        name 'CAM_CBC_Decrypt';

exports  CAM_CFB_Init           name 'CAM_CFB_Init';
exports  CAM_CFB_Reset          name 'CAM_CFB_Reset';
exports  CAM_CFB_Encrypt        name 'CAM_CFB_Encrypt';
exports  CAM_CFB_Decrypt        name 'CAM_CFB_Decrypt';

exports  CAM_OFB_Init           name 'CAM_OFB_Init';
exports  CAM_OFB_Reset          name 'CAM_OFB_Reset';
exports  CAM_OFB_Encrypt        name 'CAM_OFB_Encrypt';
exports  CAM_OFB_Decrypt        name 'CAM_OFB_Decrypt';

exports  CAM_CTR_Init           name 'CAM_CTR_Init';
exports  CAM_CTR_Reset          name 'CAM_CTR_Reset';
exports  CAM_CTR_Encrypt        name 'CAM_CTR_Encrypt';
exports  CAM_CTR_Decrypt        name 'CAM_CTR_Decrypt';
exports  CAM_SetIncProc         name 'CAM_SetIncProc';
exports  CAM_IncMSBFull         name 'CAM_IncMSBFull';
exports  CAM_IncLSBFull         name 'CAM_IncLSBFull';
exports  CAM_IncMSBPart         name 'CAM_IncMSBPart';
exports  CAM_IncLSBPart         name 'CAM_IncLSBPart';

exports  CAM_OMAC_Init          name 'CAM_OMAC_Init';
exports  CAM_OMAC_Update        name 'CAM_OMAC_Update';
exports  CAM_OMAC_Final         name 'CAM_OMAC_Final';
exports  CAM_OMAC1_Final        name 'CAM_OMAC1_Final';
exports  CAM_OMAC2_Final        name 'CAM_OMAC2_Final';

exports  CAM_EAX_Init           name 'CAM_EAX_Init';
exports  CAM_EAX_Provide_Header name 'CAM_EAX_Provide_Header';
exports  CAM_EAX_Encrypt        name 'CAM_EAX_Encrypt';
exports  CAM_EAX_Decrypt        name 'CAM_EAX_Decrypt';
exports  CAM_EAX_Final          name 'CAM_EAX_Final';
exports  CAM_EAX_Enc_Auth       name 'CAM_EAX_Enc_Auth';
exports  CAM_EAX_Dec_Veri       name 'CAM_EAX_Dec_Veri';

exports  CAM_CPRF128            name 'CAM_CPRF128';
exports  CAM_CPRF128_selftest   name 'CAM_CPRF128_selftest';

exports  CAM_CCM_Dec_Veri       name 'CAM_CCM_Dec_Veri';
exports  CAM_CCM_Dec_VeriEX     name 'CAM_CCM_Dec_VeriEX';
exports  CAM_CCM_Enc_Auth       name 'CAM_CCM_Enc_Auth';
exports  CAM_CCM_Enc_AuthEx     name 'CAM_CCM_Enc_AuthEx';

exports  CAM_GCM_Init           name 'CAM_GCM_Init';
exports  CAM_GCM_Reset_IV       name 'CAM_GCM_Reset_IV';
exports  CAM_GCM_Encrypt        name 'CAM_GCM_Encrypt';
exports  CAM_GCM_Decrypt        name 'CAM_GCM_Decrypt';
exports  CAM_GCM_Add_AAD        name 'CAM_GCM_Add_AAD';
exports  CAM_GCM_Final          name 'CAM_GCM_Final';
exports  CAM_GCM_Enc_Auth       name 'CAM_GCM_Enc_Auth';
exports  CAM_GCM_Dec_Veri       name 'CAM_GCM_Dec_Veri';


end.

