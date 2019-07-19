library ANU_DLL;

{$ifndef DLL}
  error('compile with $define DLL');
  end.
{$endif}


(*************************************************************************

 DESCRIPTION     :  DLL for Anubis (tweaked)

 REQUIREMENTS    :  D2-D7/D9-D10/D12, compile with $define DLL

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     08.08.08  W.Ehrhardt  Initial version
 0.11     16.08.08  we          Removed ANU_Reset
 0.12     13.07.09  we          ANU_DLL_Version returns PAnsiChar
 0.13     01.08.10  we          Longint ILen in ANU_xxx_En/Decrypt, ANU_OMAC_UpdateXL removed
*************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2008-2009 Wolfgang Ehrhardt

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
  anu_base, anu_ctr, anu_cfb, anu_ofb, anu_cbc, anu_ecb, anu_omac, anu_eax;

{$R *.RES}


{---------------------------------------------------------------------------}
function ANU_DLL_Version: PAnsiChar; stdcall;
  {-Return DLL version as PAnsiChar}
begin
  Result := '0.13';
end;


exports  ANU_DLL_Version        name 'ANU_DLL_Version';
exports  ANU_XorBlock           name 'ANU_XorBlock';
exports  ANU_SetFastInit        name 'ANU_SetFastInit';
exports  ANU_GetFastInit        name 'ANU_GetFastInit';
exports  ANU_Init2              name 'ANU_Init2';
exports  ANU_Init_Encr          name 'ANU_Init_Encr';
exports  ANU_Init_Decr          name 'ANU_Init_Decr';
exports  ANU_Encrypt            name 'ANU_Encrypt';
exports  ANU_Decrypt            name 'ANU_Decrypt';

exports  ANU_ECB_Init_Encr      name 'ANU_ECB_Init_Encr';
exports  ANU_ECB_Init_Decr      name 'ANU_ECB_Init_Decr';
exports  ANU_ECB_Encrypt        name 'ANU_ECB_Encrypt';
exports  ANU_ECB_Decrypt        name 'ANU_ECB_Decrypt';

exports  ANU_CBC_Init_Encr      name 'ANU_CBC_Init_Encr';
exports  ANU_CBC_Init_Decr      name 'ANU_CBC_Init_Decr';
exports  ANU_CBC_Encrypt        name 'ANU_CBC_Encrypt';
exports  ANU_CBC_Decrypt        name 'ANU_CBC_Decrypt';

exports  ANU_CFB_Init           name 'ANU_CFB_Init';
exports  ANU_CFB_Encrypt        name 'ANU_CFB_Encrypt';
exports  ANU_CFB_Decrypt        name 'ANU_CFB_Decrypt';

exports  ANU_OFB_Init           name 'ANU_OFB_Init';
exports  ANU_OFB_Encrypt        name 'ANU_OFB_Encrypt';
exports  ANU_OFB_Decrypt        name 'ANU_OFB_Decrypt';

exports  ANU_CTR_Init           name 'ANU_CTR_Init';
exports  ANU_CTR_Encrypt        name 'ANU_CTR_Encrypt';
exports  ANU_CTR_Decrypt        name 'ANU_CTR_Decrypt';
exports  ANU_SetIncProc         name 'ANU_SetIncProc';
exports  ANU_IncMSBFull         name 'ANU_IncMSBFull';
exports  ANU_IncLSBFull         name 'ANU_IncLSBFull';
exports  ANU_IncMSBPart         name 'ANU_IncMSBPart';
exports  ANU_IncLSBPart         name 'ANU_IncLSBPart';

exports  ANU_OMAC_Init          name 'ANU_OMAC_Init';
exports  ANU_OMAC_Update        name 'ANU_OMAC_Update';
exports  ANU_OMAC_Final         name 'ANU_OMAC_Final';
exports  ANU_OMAC1_Final        name 'ANU_OMAC1_Final';
exports  ANU_OMAC2_Final        name 'ANU_OMAC2_Final';
exports  ANU_OMACx_Final        name 'ANU_OMACx_Final';

exports  ANU_EAX_Init           name 'ANU_EAX_Init';
exports  ANU_EAX_Provide_Header name 'ANU_EAX_Provide_Header';
exports  ANU_EAX_Encrypt        name 'ANU_EAX_Encrypt';
exports  ANU_EAX_Decrypt        name 'ANU_EAX_Decrypt';
exports  ANU_EAX_Final          name 'ANU_EAX_Final';
exports  ANU_EAX_Enc_Auth       name 'ANU_EAX_Enc_Auth';
exports  ANU_EAX_Dec_Veri       name 'ANU_EAX_Dec_Veri';

end.

