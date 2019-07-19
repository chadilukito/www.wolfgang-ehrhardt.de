library XT_DLL;

{$ifndef DLL}
  error('compile with $define DLL');
  end.
{$endif}


(*************************************************************************

 DESCRIPTION     :  DLL for XTEA

 REQUIREMENTS    :  D2-D7/D9-D10/D12, compile with $define DLL

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.01.05  W.Ehrhardt  Initial version a la BF_DLL
 0.11     16.07.09  we          XT_DLL_Version returns PAnsiChar
 0.12     06.08.10  we          Longint ILen in XT_xxx_En/Decrypt
**************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2005-2010 Wolfgang Ehrhardt

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
  XT_base, XT_ctr, XT_cfb, XT_ofb, XT_cbc, XT_ecb;

{$R *.RES}


{---------------------------------------------------------------------------}
function XT_DLL_Version: PAnsiChar; stdcall;
  {-Return DLL version as PAnsiChar}
begin
  Result := '0.12';
end;


exports  XT_DLL_Version        name 'XT_DLL_Version';
exports  XT_XorBlock           name 'XT_XorBlock';
exports  XT_Init               name 'XT_Init';
exports  XT_Encrypt            name 'XT_Encrypt';
exports  XT_Decrypt            name 'XT_Decrypt';
exports  XT_SetFastInit        name 'XT_SetFastInit';
exports  XT_GetFastInit        name 'XT_GetFastInit';

exports  XT_ECB_Init           name 'XT_ECB_Init';
exports  XT_ECB_Reset          name 'XT_ECB_Reset';
exports  XT_ECB_Encrypt        name 'XT_ECB_Encrypt';
exports  XT_ECB_Decrypt        name 'XT_ECB_Decrypt';

exports  XT_CBC_Init           name 'XT_CBC_Init';
exports  XT_CBC_Reset          name 'XT_CBC_Reset';
exports  XT_CBC_Encrypt        name 'XT_CBC_Encrypt';
exports  XT_CBC_Decrypt        name 'XT_CBC_Decrypt';

exports  XT_CFB_Init           name 'XT_CFB_Init';
exports  XT_CFB_Reset          name 'XT_CFB_Reset';
exports  XT_CFB_Encrypt        name 'XT_CFB_Encrypt';
exports  XT_CFB_Decrypt        name 'XT_CFB_Decrypt';

exports  XT_OFB_Init           name 'XT_OFB_Init';
exports  XT_OFB_Reset          name 'XT_OFB_Reset';
exports  XT_OFB_Encrypt        name 'XT_OFB_Encrypt';
exports  XT_OFB_Decrypt        name 'XT_OFB_Decrypt';

exports  XT_CTR_Init           name 'XT_CTR_Init';
exports  XT_CTR_Reset          name 'XT_CTR_Reset';
exports  XT_CTR_Encrypt        name 'XT_CTR_Encrypt';
exports  XT_CTR_Decrypt        name 'XT_CTR_Decrypt';
exports  XT_SetIncProc         name 'XT_SetIncProc';
exports  XT_IncMSBFull         name 'XT_IncMSBFull';
exports  XT_IncLSBFull         name 'XT_IncLSBFull';
exports  XT_IncMSBPart         name 'XT_IncMSBPart';
exports  XT_IncLSBPart         name 'XT_IncLSBPart';


end.

