library SJ_DLL;

{$ifndef DLL}
  error('compile with $define DLL');
  end.
{$endif}


(*************************************************************************

 DESCRIPTION     :  DLL for SkipJack

 REQUIREMENTS    :  D2-D7/D9-D10/D12, compile with $define DLL

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     03.06.09  W.Ehrhardt  Initial version a la XT_DLL
 0.11     16.07.09  we          SJ_DLL_Version returns PAnsiChar
 0.12     06.08.10  we          Longint ILen in SJ_xxx_En/Decrypt
**************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2009-2010 Wolfgang Ehrhardt

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
  SJ_base, SJ_ctr, SJ_cfb, SJ_ofb, SJ_cbc, SJ_ecb;

{$R *.RES}


{---------------------------------------------------------------------------}
function SJ_DLL_Version: PAnsiChar; stdcall;
  {-Return DLL version as PAnsiChar}
begin
  Result := '0.12';
end;


exports  SJ_DLL_Version        name 'SJ_DLL_Version';
exports  SJ_XorBlock           name 'SJ_XorBlock';
exports  SJ_Init               name 'SJ_Init';
exports  SJ_Encrypt            name 'SJ_Encrypt';
exports  SJ_Decrypt            name 'SJ_Decrypt';
exports  SJ_SetFastInit        name 'SJ_SetFastInit';
exports  SJ_GetFastInit        name 'SJ_GetFastInit';

exports  SJ_ECB_Init           name 'SJ_ECB_Init';
exports  SJ_ECB_Reset          name 'SJ_ECB_Reset';
exports  SJ_ECB_Encrypt        name 'SJ_ECB_Encrypt';
exports  SJ_ECB_Decrypt        name 'SJ_ECB_Decrypt';

exports  SJ_CBC_Init           name 'SJ_CBC_Init';
exports  SJ_CBC_Reset          name 'SJ_CBC_Reset';
exports  SJ_CBC_Encrypt        name 'SJ_CBC_Encrypt';
exports  SJ_CBC_Decrypt        name 'SJ_CBC_Decrypt';

exports  SJ_CFB_Init           name 'SJ_CFB_Init';
exports  SJ_CFB_Reset          name 'SJ_CFB_Reset';
exports  SJ_CFB_Encrypt        name 'SJ_CFB_Encrypt';
exports  SJ_CFB_Decrypt        name 'SJ_CFB_Decrypt';

exports  SJ_OFB_Init           name 'SJ_OFB_Init';
exports  SJ_OFB_Reset          name 'SJ_OFB_Reset';
exports  SJ_OFB_Encrypt        name 'SJ_OFB_Encrypt';
exports  SJ_OFB_Decrypt        name 'SJ_OFB_Decrypt';

exports  SJ_CTR_Init           name 'SJ_CTR_Init';
exports  SJ_CTR_Reset          name 'SJ_CTR_Reset';
exports  SJ_CTR_Encrypt        name 'SJ_CTR_Encrypt';
exports  SJ_CTR_Decrypt        name 'SJ_CTR_Decrypt';
exports  SJ_SetIncProc         name 'SJ_SetIncProc';
exports  SJ_IncMSBFull         name 'SJ_IncMSBFull';
exports  SJ_IncLSBFull         name 'SJ_IncLSBFull';
exports  SJ_IncMSBPart         name 'SJ_IncMSBPart';
exports  SJ_IncLSBPart         name 'SJ_IncLSBPart';


(*

function  SJ_Init(const Key; KeyBytes: word; var ctx: TSJContext): integer;
  {-SkipJack context initialization}

procedure SJ_Encrypt(var ctx: TSJContext; const BI: TSJBlock; var BO: TSJBlock);
  {-encrypt one block}

procedure SJ_Decrypt(var ctx: TSJContext; const BI: TSJBlock; var BO: TSJBlock);
  {-decrypt one block}

procedure SJ_XorBlock(const B1, B2: TSJBlock; var B3: TSJBlock);
  {-xor two blocks, result in third}

procedure SJ_SetFastInit(value: boolean);
  {-set FastInit variable}

function  SJ_GetFastInit: boolean;
  {-Returns FastInit variable}



function  SJ_CBC_Init(const Key; KeyBytes: word; const IV: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size, save IV}

procedure SJ_CBC_Reset(const IV: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, save IV}

function  SJ_CBC_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  SJ_CBC_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  SJ_CFB_Init(const Key; KeyBytes: word; const IV: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size, encrypt IV}

procedure SJ_CFB_Reset(const IV: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SJ_CFB_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB mode}

function  SJ_CFB_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB mode}



function  SJ_CTR_Init(const Key; KeyBytes: word; const CTR: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if inv. key size, encrypt CTR}

procedure SJ_CTR_Reset(const CTR: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}

function  SJ_CTR_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  SJ_CTR_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  SJ_SetIncProc(IncP: TSJIncProc; var ctx: TSJContext): integer;
  {-Set user supplied IncCTR proc}

procedure SJ_IncMSBFull(var CTR: TSJBlock);
  {-Increment CTR[7]..CTR[0]}

procedure SJ_IncLSBFull(var CTR: TSJBlock);
  {-Increment CTR[0]..CTR[7]}

procedure SJ_IncMSBPart(var CTR: TSJBlock);
  {-Increment CTR[7]..CTR[4]}

procedure SJ_IncLSBPart(var CTR: TSJBlock);
  {-Increment CTR[0]..CTR[3]}



function  SJ_ECB_Init({const Key; KeyBytes: word; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size}

procedure SJ_ECB_Reset(var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag}

function  SJ_ECB_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  SJ_ECB_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  SJ_OFB_Init(const Key; KeyBits: word; const IV: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size, encrypt IV}

procedure SJ_OFB_Reset(const IV: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SJ_OFB_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  SJ_OFB_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}
*)



end.

