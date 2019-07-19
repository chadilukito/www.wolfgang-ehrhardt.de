library SC_DLL;

{$ifndef DLL}
  error('compile with $define DLL');
  end.
{$endif}


(*************************************************************************

 DESCRIPTION     :  DLL for SHACAL-2

 REQUIREMENTS    :  D2-D7/D9-D10/D12, compile with $define DLL

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     02.01.05  W.Ehrhardt  Initial version a la BF.DLL
 0.11     16.07.09  we          SC_DLL_Version returns PAnsiChar
 0.12     06.08.10  we          Longint ILen in SC_xxx_En/Decrypt
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
  SC_Base, SC_CTR, SC_CFB, SC_OFB, SC_CBC, SC_ECB;

{$R *.RES}


{---------------------------------------------------------------------------}
function SC_DLL_Version: PAnsiChar; stdcall;
  {-Return DLL version as PAnsiChar}
begin
  Result := '0.12';
end;


exports  SC_DLL_Version        name 'SC_DLL_Version';
exports  SC_XorBlock           name 'SC_XorBlock';
exports  SC_Init               name 'SC_Init';
exports  SC_Encrypt            name 'SC_Encrypt';
exports  SC_Decrypt            name 'SC_Decrypt';
exports  SC_SetFastInit        name 'SC_SetFastInit';
exports  SC_GetFastInit        name 'SC_GetFastInit';

exports  SC_ECB_Init           name 'SC_ECB_Init';
exports  SC_ECB_Reset          name 'SC_ECB_Reset';
exports  SC_ECB_Encrypt        name 'SC_ECB_Encrypt';
exports  SC_ECB_Decrypt        name 'SC_ECB_Decrypt';

exports  SC_CBC_Init           name 'SC_CBC_Init';
exports  SC_CBC_Reset          name 'SC_CBC_Reset';
exports  SC_CBC_Encrypt        name 'SC_CBC_Encrypt';
exports  SC_CBC_Decrypt        name 'SC_CBC_Decrypt';

exports  SC_CFB_Init           name 'SC_CFB_Init';
exports  SC_CFB_Reset          name 'SC_CFB_Reset';
exports  SC_CFB_Encrypt        name 'SC_CFB_Encrypt';
exports  SC_CFB_Decrypt        name 'SC_CFB_Decrypt';

exports  SC_OFB_Init           name 'SC_OFB_Init';
exports  SC_OFB_Reset          name 'SC_OFB_Reset';
exports  SC_OFB_Encrypt        name 'SC_OFB_Encrypt';
exports  SC_OFB_Decrypt        name 'SC_OFB_Decrypt';

exports  SC_CTR_Init           name 'SC_CTR_Init';
exports  SC_CTR_Reset          name 'SC_CTR_Reset';
exports  SC_CTR_Encrypt        name 'SC_CTR_Encrypt';
exports  SC_CTR_Decrypt        name 'SC_CTR_Decrypt';
exports  SC_SetIncProc         name 'SC_SetIncProc';
exports  SC_IncMSBFull         name 'SC_IncMSBFull';
exports  SC_IncLSBFull         name 'SC_IncLSBFull';
exports  SC_IncMSBPart         name 'SC_IncMSBPart';
exports  SC_IncLSBPart         name 'SC_IncLSBPart';


(*

function  SC_Init(const Key; KeyBytes: word; var ctx: TSCContext): integer;
  {-SHACAL-2 context SBox initialization}

procedure SC_Encrypt(var ctx: TSCContext; const BI: TSCBlock; var BO: TSCBlock);
  {-encrypt one block (in ECB mode)}

procedure SC_Decrypt(var ctx: TSCContext; const BI: TSCBlock; var BO: TSCBlock);
  {-decrypt one block (in ECB mode)}

procedure SC_XorBlock(const B1, B2: TSCBlock; var B3: TSCBlock);
  {-xor two blocks, result in third}

procedure SC_SetFastInit(value: boolean);
  {-set FastInit variable}

function  SC_GetFastInit: boolean;
  {-Returns FastInit variable}



function  SC_CBC_Init(const Key; KeyBytes: word; const IV: TSCBlock; var ctx: TSCContext): integer;
  {-SC key expansion, error if invalid key size, save IV}

procedure SC_CBC_Reset(const IV: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, save IV}

function  SC_CBC_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}

function  SC_CBC_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}



function  SC_CFB_Init(const Key; KeyBytes: word; const IV: TSCBlock; var ctx: TSCContext): integer;
  {-SC key expansion, error if invalid key size, encrypt IV}

procedure SC_CFB_Reset(const IV: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SC_CFB_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB mode}

function  SC_CFB_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB mode}



function  SC_CTR_Init(const Key; KeyBytes: word; const CTR: TSCBlock; var ctx: TSCContext): integer;
  {-SC key expansion, error if inv. key size, encrypt CTR}

procedure SC_CTR_Reset(const CTR: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}

function  SC_CTR_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}

function  SC_CTR_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}

function  SC_SetIncProc(IncP: TSCIncProc; var ctx: TSCContext): integer;
  {-Set user supplied IncCTR proc}

procedure SC_IncMSBFull(var CTR: TSCBlock);
  {-Increment CTR[31]..CTR[0]}

procedure SC_IncLSBFull(var CTR: TSCBlock);
  {-Increment CTR[0]..CTR[31]}

procedure SC_IncMSBPart(var CTR: TSCBlock);
  {-Increment CTR[31]..CTR[16]}

procedure SC_IncLSBPart(var CTR: TSCBlock);
  {-Increment CTR[0]..CTR[15]}



function  SC_ECB_Init({const Key; KeyBytes: word; var ctx: TSCContext): integer;
  {-SC key expansion, error if invalid key size}

procedure SC_ECB_Reset(var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag}

function  SC_ECB_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}

function  SC_ECB_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}



function  SC_OFB_Init(const Key; KeyBits: word; const IV: TSCBlock; var ctx: TSCContext): integer;
  {-SC key expansion, error if invalid key size, encrypt IV}

procedure SC_OFB_Reset(const IV: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

function  SC_OFB_Encrypt(ptp, ctp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}

function  SC_OFB_Decrypt(ctp, ptp: Pointer; ILen: word; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}

*)



end.

