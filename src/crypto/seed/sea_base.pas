unit SEA_Base;

(*************************************************************************

 DESCRIPTION   :  SEED Encryption basic routines

 REQUIREMENTS  :  TP5-7, D1-D7/D9-D10/D12/D17-D18/D25S, FPC, VP, WDOSX

 EXTERNAL DATA :  ---

 MEMORY USAGE  :  4.0 KB static data

 DISPLAY MODE  :  ---

 REFERENCES    :  [1] H.J. Lee et al, The SEED Encryption Algorithm, 2005
                      http://tools.ietf.org/html/rfc4269

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.01     03.06.07  W.Ehrhardt  Initial BP7 SEA_Init
 0.02     03.06.07  we          FastInit/SEA_Reset
 0.03     03.06.07  we          SEA_XorBlock
 0.04     03.06.07  we          SEA_En/Decrypt
 0.05     07.06.07  we          Function SG: BIT16 and BASM16 versions
 0.06     07.06.07  we          SEA_Init/BIT16: 64 bit rotation with move()
 0.07     08.06.07  we          SEA_Init/BIT16: uses byte H instead of longint T
 0.08     26.07.10  we          SEA_Err_Invalid_16Bit_Length
 0.09     28.07.10  we          SEA_Err_CTR_SeekOffset
 0.10     21.07.12  we          64-bit adjustments
 0.11     25.12.12  we          {$J+} if needed
 0.12     23.11.17  we          RB for CPUARM
 **************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2007-17 Wolfgang Ehrhardt

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

{$i std.inc}


interface

const
  SEA_Err_Invalid_Key_Size       = -1;  {Key size in bits not 128, 192, or 256}
  SEA_Err_Invalid_Length         = -3;  {No full block for cipher stealing}
  SEA_Err_Data_After_Short_Block = -4;  {Short block must be last}
  SEA_Err_MultipleIncProcs       = -5;  {More than one IncProc Setting}
  SEA_Err_NIL_Pointer            = -6;  {nil pointer to block with nonzero length}
  SEA_Err_CTR_SeekOffset         = -15; {Negative offset in SEA_CTR_Seek}
  SEA_Err_Invalid_16Bit_Length   = -20; {Pointer + Offset > $FFFF for 16 bit code}

type
  TSEARndKey = packed array[0..31] of longint;  {Round key schedule}
  TSEABlock  = packed array[0..15] of byte;     {128 bit block}
  PSEABlock  = ^TSEABlock;

type
  TSEAIncProc = procedure(var CTR: TSEABlock);   {user supplied IncCTR proc}
                   {$ifdef DLL} stdcall; {$endif}
type
  TSEAContext = packed record
                 IV      : TSEABlock;   {IV or CTR              }
                 buf     : TSEABlock;   {Work buffer            }
                 bLen    : word;        {Bytes used in buf      }
                 Flag    : word;        {Bit 1: Short block     }
                 IncProc : TSEAIncProc; {Increment proc CTR-Mode}
                 RK      : TSEARndKey;  {Round keys             }
               end;

const
  SEABLKSIZE  = sizeof(TSEABlock);     {SEED block size in bytes}


{$ifdef CONST}
function  SEA_Init(const Key; KeyBits: word; var ctx: TSEAContext): integer;
  {-SEED context/round key initialization}
  {$ifdef DLL} stdcall; {$endif}

procedure SEA_Encrypt(var ctx: TSEAContext; const BI: TSEABlock; var BO: TSEABlock);
  {-encrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure SEA_Decrypt(var ctx: TSEAContext; const BI: TSEABlock; var BO: TSEABlock);
  {-decrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure SEA_XorBlock(const B1, B2: TSEABlock; var B3: TSEABlock);
  {-xor two blocks, result in third}
  {$ifdef DLL} stdcall; {$endif}
{$else}
function  SEA_Init(var Key; KeyBits: word; var ctx: TSEAContext): integer;
  {-SEED context/round key initialization}

procedure SEA_Encrypt(var ctx: TSEAContext; var BI: TSEABlock; var BO: TSEABlock);
  {-encrypt one block (in ECB mode)}

procedure SEA_Decrypt(var ctx: TSEAContext; var BI: TSEABlock; var BO: TSEABlock);
  {-decrypt one block (in ECB mode)}

procedure SEA_XorBlock(var B1, B2: TSEABlock; var B3: TSEABlock);
  {-xor two blocks, result in third}
{$endif}


procedure SEA_Reset(var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag}
  {$ifdef DLL} stdcall; {$endif}

procedure SEA_SetFastInit(value: boolean);
  {-set FastInit variable}
  {$ifdef DLL} stdcall; {$endif}

function  SEA_GetFastInit: boolean;
  {-Returns FastInit variable}
  {$ifdef DLL} stdcall; {$endif}


implementation


{$ifdef D4Plus}
var
{$else}
{$ifdef J_OPT} {$J+} {$endif}
const
{$endif}
  FastInit : boolean = true;    {Clear only necessary context data at init}
                                {IV and buf remain uninitialized}

type
  TXSBox = packed array[0..255] of longint; {Extended S-box}
  TWA4   = packed array[0..3] of longint;   {Block as array of longint}

{$ifdef StrictLong}
  {$warnings off}
  {$R-} {avoid D9+ errors!}
{$endif}

{Extended S-boxes}
const
  SS0: TXSBox = ($2989A1A8, $05858184, $16C6D2D4, $13C3D3D0, $14445054, $1D0D111C, $2C8CA0AC, $25052124,
                 $1D4D515C, $03434340, $18081018, $1E0E121C, $11415150, $3CCCF0FC, $0ACAC2C8, $23436360,
                 $28082028, $04444044, $20002020, $1D8D919C, $20C0E0E0, $22C2E2E0, $08C8C0C8, $17071314,
                 $2585A1A4, $0F8F838C, $03030300, $3B4B7378, $3B8BB3B8, $13031310, $12C2D2D0, $2ECEE2EC,
                 $30407070, $0C8C808C, $3F0F333C, $2888A0A8, $32023230, $1DCDD1DC, $36C6F2F4, $34447074,
                 $2CCCE0EC, $15859194, $0B0B0308, $17475354, $1C4C505C, $1B4B5358, $3D8DB1BC, $01010100,
                 $24042024, $1C0C101C, $33437370, $18889098, $10001010, $0CCCC0CC, $32C2F2F0, $19C9D1D8,
                 $2C0C202C, $27C7E3E4, $32427270, $03838380, $1B8B9398, $11C1D1D0, $06868284, $09C9C1C8,
                 $20406060, $10405050, $2383A3A0, $2BCBE3E8, $0D0D010C, $3686B2B4, $1E8E929C, $0F4F434C,
                 $3787B3B4, $1A4A5258, $06C6C2C4, $38487078, $2686A2A4, $12021210, $2F8FA3AC, $15C5D1D4,
                 $21416160, $03C3C3C0, $3484B0B4, $01414140, $12425250, $3D4D717C, $0D8D818C, $08080008,
                 $1F0F131C, $19899198, $00000000, $19091118, $04040004, $13435350, $37C7F3F4, $21C1E1E0,
                 $3DCDF1FC, $36467274, $2F0F232C, $27072324, $3080B0B0, $0B8B8388, $0E0E020C, $2B8BA3A8,
                 $2282A2A0, $2E4E626C, $13839390, $0D4D414C, $29496168, $3C4C707C, $09090108, $0A0A0208,
                 $3F8FB3BC, $2FCFE3EC, $33C3F3F0, $05C5C1C4, $07878384, $14041014, $3ECEF2FC, $24446064,
                 $1ECED2DC, $2E0E222C, $0B4B4348, $1A0A1218, $06060204, $21012120, $2B4B6368, $26466264,
                 $02020200, $35C5F1F4, $12829290, $0A8A8288, $0C0C000C, $3383B3B0, $3E4E727C, $10C0D0D0,
                 $3A4A7278, $07474344, $16869294, $25C5E1E4, $26062224, $00808080, $2D8DA1AC, $1FCFD3DC,
                 $2181A1A0, $30003030, $37073334, $2E8EA2AC, $36063234, $15051114, $22022220, $38083038,
                 $34C4F0F4, $2787A3A4, $05454144, $0C4C404C, $01818180, $29C9E1E8, $04848084, $17879394,
                 $35053134, $0BCBC3C8, $0ECEC2CC, $3C0C303C, $31417170, $11011110, $07C7C3C4, $09898188,
                 $35457174, $3BCBF3F8, $1ACAD2D8, $38C8F0F8, $14849094, $19495158, $02828280, $04C4C0C4,
                 $3FCFF3FC, $09494148, $39093138, $27476364, $00C0C0C0, $0FCFC3CC, $17C7D3D4, $3888B0B8,
                 $0F0F030C, $0E8E828C, $02424240, $23032320, $11819190, $2C4C606C, $1BCBD3D8, $2484A0A4,
                 $34043034, $31C1F1F0, $08484048, $02C2C2C0, $2F4F636C, $3D0D313C, $2D0D212C, $00404040,
                 $3E8EB2BC, $3E0E323C, $3C8CB0BC, $01C1C1C0, $2A8AA2A8, $3A8AB2B8, $0E4E424C, $15455154,
                 $3B0B3338, $1CCCD0DC, $28486068, $3F4F737C, $1C8C909C, $18C8D0D8, $0A4A4248, $16465254,
                 $37477374, $2080A0A0, $2DCDE1EC, $06464244, $3585B1B4, $2B0B2328, $25456164, $3ACAF2F8,
                 $23C3E3E0, $3989B1B8, $3181B1B0, $1F8F939C, $1E4E525C, $39C9F1F8, $26C6E2E4, $3282B2B0,
                 $31013130, $2ACAE2E8, $2D4D616C, $1F4F535C, $24C4E0E4, $30C0F0F0, $0DCDC1CC, $08888088,
                 $16061214, $3A0A3238, $18485058, $14C4D0D4, $22426260, $29092128, $07070304, $33033330,
                 $28C8E0E8, $1B0B1318, $05050104, $39497178, $10809090, $2A4A6268, $2A0A2228, $1A8A9298);

  SS1: TXSBox = ($38380830, $E828C8E0, $2C2D0D21, $A42686A2, $CC0FCFC3, $DC1ECED2, $B03383B3, $B83888B0,
                 $AC2F8FA3, $60204060, $54154551, $C407C7C3, $44044440, $6C2F4F63, $682B4B63, $581B4B53,
                 $C003C3C3, $60224262, $30330333, $B43585B1, $28290921, $A02080A0, $E022C2E2, $A42787A3,
                 $D013C3D3, $90118191, $10110111, $04060602, $1C1C0C10, $BC3C8CB0, $34360632, $480B4B43,
                 $EC2FCFE3, $88088880, $6C2C4C60, $A82888A0, $14170713, $C404C4C0, $14160612, $F434C4F0,
                 $C002C2C2, $44054541, $E021C1E1, $D416C6D2, $3C3F0F33, $3C3D0D31, $8C0E8E82, $98188890,
                 $28280820, $4C0E4E42, $F436C6F2, $3C3E0E32, $A42585A1, $F839C9F1, $0C0D0D01, $DC1FCFD3,
                 $D818C8D0, $282B0B23, $64264662, $783A4A72, $24270723, $2C2F0F23, $F031C1F1, $70324272,
                 $40024242, $D414C4D0, $40014141, $C000C0C0, $70334373, $64274763, $AC2C8CA0, $880B8B83,
                 $F437C7F3, $AC2D8DA1, $80008080, $1C1F0F13, $C80ACAC2, $2C2C0C20, $A82A8AA2, $34340430,
                 $D012C2D2, $080B0B03, $EC2ECEE2, $E829C9E1, $5C1D4D51, $94148490, $18180810, $F838C8F0,
                 $54174753, $AC2E8EA2, $08080800, $C405C5C1, $10130313, $CC0DCDC1, $84068682, $B83989B1,
                 $FC3FCFF3, $7C3D4D71, $C001C1C1, $30310131, $F435C5F1, $880A8A82, $682A4A62, $B03181B1,
                 $D011C1D1, $20200020, $D417C7D3, $00020202, $20220222, $04040400, $68284860, $70314171,
                 $04070703, $D81BCBD3, $9C1D8D91, $98198991, $60214161, $BC3E8EB2, $E426C6E2, $58194951,
                 $DC1DCDD1, $50114151, $90108090, $DC1CCCD0, $981A8A92, $A02383A3, $A82B8BA3, $D010C0D0,
                 $80018181, $0C0F0F03, $44074743, $181A0A12, $E023C3E3, $EC2CCCE0, $8C0D8D81, $BC3F8FB3,
                 $94168692, $783B4B73, $5C1C4C50, $A02282A2, $A02181A1, $60234363, $20230323, $4C0D4D41,
                 $C808C8C0, $9C1E8E92, $9C1C8C90, $383A0A32, $0C0C0C00, $2C2E0E22, $B83A8AB2, $6C2E4E62,
                 $9C1F8F93, $581A4A52, $F032C2F2, $90128292, $F033C3F3, $48094941, $78384870, $CC0CCCC0,
                 $14150511, $F83BCBF3, $70304070, $74354571, $7C3F4F73, $34350531, $10100010, $00030303,
                 $64244460, $6C2D4D61, $C406C6C2, $74344470, $D415C5D1, $B43484B0, $E82ACAE2, $08090901,
                 $74364672, $18190911, $FC3ECEF2, $40004040, $10120212, $E020C0E0, $BC3D8DB1, $04050501,
                 $F83ACAF2, $00010101, $F030C0F0, $282A0A22, $5C1E4E52, $A82989A1, $54164652, $40034343,
                 $84058581, $14140410, $88098981, $981B8B93, $B03080B0, $E425C5E1, $48084840, $78394971,
                 $94178793, $FC3CCCF0, $1C1E0E12, $80028282, $20210121, $8C0C8C80, $181B0B13, $5C1F4F53,
                 $74374773, $54144450, $B03282B2, $1C1D0D11, $24250521, $4C0F4F43, $00000000, $44064642,
                 $EC2DCDE1, $58184850, $50124252, $E82BCBE3, $7C3E4E72, $D81ACAD2, $C809C9C1, $FC3DCDF1,
                 $30300030, $94158591, $64254561, $3C3C0C30, $B43686B2, $E424C4E0, $B83B8BB3, $7C3C4C70,
                 $0C0E0E02, $50104050, $38390931, $24260622, $30320232, $84048480, $68294961, $90138393,
                 $34370733, $E427C7E3, $24240420, $A42484A0, $C80BCBC3, $50134353, $080A0A02, $84078783,
                 $D819C9D1, $4C0C4C40, $80038383, $8C0F8F83, $CC0ECEC2, $383B0B33, $480A4A42, $B43787B3);

  SS2: TXSBox = ($A1A82989, $81840585, $D2D416C6, $D3D013C3, $50541444, $111C1D0D, $A0AC2C8C, $21242505,
                 $515C1D4D, $43400343, $10181808, $121C1E0E, $51501141, $F0FC3CCC, $C2C80ACA, $63602343,
                 $20282808, $40440444, $20202000, $919C1D8D, $E0E020C0, $E2E022C2, $C0C808C8, $13141707,
                 $A1A42585, $838C0F8F, $03000303, $73783B4B, $B3B83B8B, $13101303, $D2D012C2, $E2EC2ECE,
                 $70703040, $808C0C8C, $333C3F0F, $A0A82888, $32303202, $D1DC1DCD, $F2F436C6, $70743444,
                 $E0EC2CCC, $91941585, $03080B0B, $53541747, $505C1C4C, $53581B4B, $B1BC3D8D, $01000101,
                 $20242404, $101C1C0C, $73703343, $90981888, $10101000, $C0CC0CCC, $F2F032C2, $D1D819C9,
                 $202C2C0C, $E3E427C7, $72703242, $83800383, $93981B8B, $D1D011C1, $82840686, $C1C809C9,
                 $60602040, $50501040, $A3A02383, $E3E82BCB, $010C0D0D, $B2B43686, $929C1E8E, $434C0F4F,
                 $B3B43787, $52581A4A, $C2C406C6, $70783848, $A2A42686, $12101202, $A3AC2F8F, $D1D415C5,
                 $61602141, $C3C003C3, $B0B43484, $41400141, $52501242, $717C3D4D, $818C0D8D, $00080808,
                 $131C1F0F, $91981989, $00000000, $11181909, $00040404, $53501343, $F3F437C7, $E1E021C1,
                 $F1FC3DCD, $72743646, $232C2F0F, $23242707, $B0B03080, $83880B8B, $020C0E0E, $A3A82B8B,
                 $A2A02282, $626C2E4E, $93901383, $414C0D4D, $61682949, $707C3C4C, $01080909, $02080A0A,
                 $B3BC3F8F, $E3EC2FCF, $F3F033C3, $C1C405C5, $83840787, $10141404, $F2FC3ECE, $60642444,
                 $D2DC1ECE, $222C2E0E, $43480B4B, $12181A0A, $02040606, $21202101, $63682B4B, $62642646,
                 $02000202, $F1F435C5, $92901282, $82880A8A, $000C0C0C, $B3B03383, $727C3E4E, $D0D010C0,
                 $72783A4A, $43440747, $92941686, $E1E425C5, $22242606, $80800080, $A1AC2D8D, $D3DC1FCF,
                 $A1A02181, $30303000, $33343707, $A2AC2E8E, $32343606, $11141505, $22202202, $30383808,
                 $F0F434C4, $A3A42787, $41440545, $404C0C4C, $81800181, $E1E829C9, $80840484, $93941787,
                 $31343505, $C3C80BCB, $C2CC0ECE, $303C3C0C, $71703141, $11101101, $C3C407C7, $81880989,
                 $71743545, $F3F83BCB, $D2D81ACA, $F0F838C8, $90941484, $51581949, $82800282, $C0C404C4,
                 $F3FC3FCF, $41480949, $31383909, $63642747, $C0C000C0, $C3CC0FCF, $D3D417C7, $B0B83888,
                 $030C0F0F, $828C0E8E, $42400242, $23202303, $91901181, $606C2C4C, $D3D81BCB, $A0A42484,
                 $30343404, $F1F031C1, $40480848, $C2C002C2, $636C2F4F, $313C3D0D, $212C2D0D, $40400040,
                 $B2BC3E8E, $323C3E0E, $B0BC3C8C, $C1C001C1, $A2A82A8A, $B2B83A8A, $424C0E4E, $51541545,
                 $33383B0B, $D0DC1CCC, $60682848, $737C3F4F, $909C1C8C, $D0D818C8, $42480A4A, $52541646,
                 $73743747, $A0A02080, $E1EC2DCD, $42440646, $B1B43585, $23282B0B, $61642545, $F2F83ACA,
                 $E3E023C3, $B1B83989, $B1B03181, $939C1F8F, $525C1E4E, $F1F839C9, $E2E426C6, $B2B03282,
                 $31303101, $E2E82ACA, $616C2D4D, $535C1F4F, $E0E424C4, $F0F030C0, $C1CC0DCD, $80880888,
                 $12141606, $32383A0A, $50581848, $D0D414C4, $62602242, $21282909, $03040707, $33303303,
                 $E0E828C8, $13181B0B, $01040505, $71783949, $90901080, $62682A4A, $22282A0A, $92981A8A);

  SS3: TXSBox = ($08303838, $C8E0E828, $0D212C2D, $86A2A426, $CFC3CC0F, $CED2DC1E, $83B3B033, $88B0B838,
                 $8FA3AC2F, $40606020, $45515415, $C7C3C407, $44404404, $4F636C2F, $4B63682B, $4B53581B,
                 $C3C3C003, $42626022, $03333033, $85B1B435, $09212829, $80A0A020, $C2E2E022, $87A3A427,
                 $C3D3D013, $81919011, $01111011, $06020406, $0C101C1C, $8CB0BC3C, $06323436, $4B43480B,
                 $CFE3EC2F, $88808808, $4C606C2C, $88A0A828, $07131417, $C4C0C404, $06121416, $C4F0F434,
                 $C2C2C002, $45414405, $C1E1E021, $C6D2D416, $0F333C3F, $0D313C3D, $8E828C0E, $88909818,
                 $08202828, $4E424C0E, $C6F2F436, $0E323C3E, $85A1A425, $C9F1F839, $0D010C0D, $CFD3DC1F,
                 $C8D0D818, $0B23282B, $46626426, $4A72783A, $07232427, $0F232C2F, $C1F1F031, $42727032,
                 $42424002, $C4D0D414, $41414001, $C0C0C000, $43737033, $47636427, $8CA0AC2C, $8B83880B,
                 $C7F3F437, $8DA1AC2D, $80808000, $0F131C1F, $CAC2C80A, $0C202C2C, $8AA2A82A, $04303434,
                 $C2D2D012, $0B03080B, $CEE2EC2E, $C9E1E829, $4D515C1D, $84909414, $08101818, $C8F0F838,
                 $47535417, $8EA2AC2E, $08000808, $C5C1C405, $03131013, $CDC1CC0D, $86828406, $89B1B839,
                 $CFF3FC3F, $4D717C3D, $C1C1C001, $01313031, $C5F1F435, $8A82880A, $4A62682A, $81B1B031,
                 $C1D1D011, $00202020, $C7D3D417, $02020002, $02222022, $04000404, $48606828, $41717031,
                 $07030407, $CBD3D81B, $8D919C1D, $89919819, $41616021, $8EB2BC3E, $C6E2E426, $49515819,
                 $CDD1DC1D, $41515011, $80909010, $CCD0DC1C, $8A92981A, $83A3A023, $8BA3A82B, $C0D0D010,
                 $81818001, $0F030C0F, $47434407, $0A12181A, $C3E3E023, $CCE0EC2C, $8D818C0D, $8FB3BC3F,
                 $86929416, $4B73783B, $4C505C1C, $82A2A022, $81A1A021, $43636023, $03232023, $4D414C0D,
                 $C8C0C808, $8E929C1E, $8C909C1C, $0A32383A, $0C000C0C, $0E222C2E, $8AB2B83A, $4E626C2E,
                 $8F939C1F, $4A52581A, $C2F2F032, $82929012, $C3F3F033, $49414809, $48707838, $CCC0CC0C,
                 $05111415, $CBF3F83B, $40707030, $45717435, $4F737C3F, $05313435, $00101010, $03030003,
                 $44606424, $4D616C2D, $C6C2C406, $44707434, $C5D1D415, $84B0B434, $CAE2E82A, $09010809,
                 $46727436, $09111819, $CEF2FC3E, $40404000, $02121012, $C0E0E020, $8DB1BC3D, $05010405,
                 $CAF2F83A, $01010001, $C0F0F030, $0A22282A, $4E525C1E, $89A1A829, $46525416, $43434003,
                 $85818405, $04101414, $89818809, $8B93981B, $80B0B030, $C5E1E425, $48404808, $49717839,
                 $87939417, $CCF0FC3C, $0E121C1E, $82828002, $01212021, $8C808C0C, $0B13181B, $4F535C1F,
                 $47737437, $44505414, $82B2B032, $0D111C1D, $05212425, $4F434C0F, $00000000, $46424406,
                 $CDE1EC2D, $48505818, $42525012, $CBE3E82B, $4E727C3E, $CAD2D81A, $C9C1C809, $CDF1FC3D,
                 $00303030, $85919415, $45616425, $0C303C3C, $86B2B436, $C4E0E424, $8BB3B83B, $4C707C3C,
                 $0E020C0E, $40505010, $09313839, $06222426, $02323032, $84808404, $49616829, $83939013,
                 $07333437, $C7E3E427, $04202424, $84A0A424, $CBC3C80B, $43535013, $0A02080A, $87838407,
                 $C9D1D819, $4C404C0C, $83838003, $8F838C0F, $CEC2CC0E, $0B33383B, $4A42480A, $87B3B437);

  KC: array[0..15] of longint = ($9E3779B9, $3C6EF373, $78DDE6E6, $F1BBCDCC,
                                 $E3779B99, $C6EF3733, $8DDE6E67, $1BBCDCCF,
                                 $3779B99E, $6EF3733C, $DDE6E678, $BBCDCCF1,
                                 $779B99E3, $EF3733C6, $DE6E678D, $BCDCCF1B);

{$ifdef StrictLong}
  {$warnings on}
  {$ifdef RangeChecks_on}
    {$R+}
  {$endif}
{$endif}


{$ifndef BIT16}

{32/64-bit code}
{$ifdef BIT64}
{---------------------------------------------------------------------------}
function RB(A: longint): longint;  {$ifdef HAS_INLINE} inline; {$endif}
  {-reverse byte order in longint}
begin
  RB := ((A and $FF) shl 24) or ((A and $FF00) shl 8) or ((A and $FF0000) shr 8) or ((A and longint($FF000000)) shr 24);
end;
{$else}
{$ifdef CPUARM}
{---------------------------------------------------------------------------}
function RB(A: longint): longint;  {$ifdef HAS_INLINE} inline; {$endif}
  {-reverse byte order in longint}
begin
  RB := ((A and $FF) shl 24) or ((A and $FF00) shl 8) or ((A and $FF0000) shr 8) or ((A and longint($FF000000)) shr 24);
end;
{$else}
{---------------------------------------------------------------------------}
function RB(A: longint): longint; assembler;  {&frame-}
  {-reverse byte order in longint}
asm
  {$ifdef LoadArgs}
    mov eax,[A]
  {$endif}
    xchg al,ah
    rol  eax,16
    xchg al,ah
end;
{$endif}
{$endif}

{$else} {16-bit}

{---------------------------------------------------------------------------}
function RB(A: longint): longint;
  {-reverse byte order in longint}
inline(
  $58/              {pop    ax   }
  $5A/              {pop    dx   }
  $86/$C6/          {xchg   dh,al}
  $86/$E2);         {xchg   dl,ah}
{$endif}



{$ifdef BASM16}
{---------------------------------------------------------------------------}
procedure SEA_XorBlock({$ifdef CONST} const {$else} var {$endif} B1, B2: TSEABlock; var B3: TSEABlock);
  {-xor two blocks, result in third}
begin
  asm
             mov   di,ds
             lds   si,[B1]
    db $66;  mov   ax,[si]
    db $66;  mov   bx,[si+4]
    db $66;  mov   cx,[si+8]
    db $66;  mov   dx,[si+12]
             lds   si,[B2]
    db $66;  xor   ax,[si]
    db $66;  xor   bx,[si+4]
    db $66;  xor   cx,[si+8]
    db $66;  xor   dx,[si+12]
             lds   si,[B3]
    db $66;  mov   [si],ax
    db $66;  mov   [si+4],bx
    db $66;  mov   [si+8],cx
    db $66;  mov   [si+12],dx
             mov   ds,di
  end;
end;

{$else}

{---------------------------------------------------------------------------}
procedure SEA_XorBlock({$ifdef CONST} const {$else} var {$endif} B1, B2: TSEABlock; var B3: TSEABlock);
  {-xor two blocks, result in third}
var
  a1: TWA4 absolute B1;
  a2: TWA4 absolute B2;
  a3: TWA4 absolute B3;
begin
  a3[0] := a1[0] xor a2[0];
  a3[1] := a1[1] xor a2[1];
  a3[2] := a1[2] xor a2[2];
  a3[3] := a1[3] xor a2[3];
end;

{$endif BASM16}


{$ifndef BIT16}
{---------------------------------------------------------------------------}
function SG(x: longint): longint; {$ifdef HAS_INLINE} inline; {$endif}
begin
  SG := SS3[x shr 24] xor SS2[x shr 16 and $FF] xor SS1[x shr 8 and $FF]  xor SS0[x and $FF];
end;
{$else}
  {$ifdef BASM16}
    {---------------------------------------------------------------------------}
    function SG(x: longint): longint; near; assembler;
    asm
      { op  eax, mem[4*bx] is calculated as           }
      { lea esi, [ebx + 2*ebx]                        }
      { op  eax, mem[ebx+esi]                         }
      { lea esi,[ebx+2*ebx] = db $66,$67,$8D,$34,$5B; }
              mov  cx,word ptr [x]
              mov  dx,word ptr [x+2]
      db $66; sub  bx,bx
              mov  bl,cl
      db $66,$67,$8D,$34,$5B;
      db $66; mov  ax,word ptr SS0[bx+si]
              mov  bl,ch
      db $66,$67,$8D,$34,$5B;
      db $66; xor  ax,word ptr SS1[bx+si]
              mov  bl,dl
      db $66,$67,$8D,$34,$5B;
      db $66; xor  ax,word ptr SS2[bx+si]
              mov  bl,dh
      db $66,$67,$8D,$34,$5B;
      db $66; xor  ax,word ptr SS3[bx+si]
      db $66; mov  dx,ax
      db $66; shr  dx,16
    end;
  {$else}
    {---------------------------------------------------------------------------}
    function SG(x: longint): longint;
    var
      b: packed array[0..3] of byte absolute x;
    begin
      SG := SS3[b[3]] xor SS2[b[2]] xor SS1[b[1]] xor SS0[b[0]];
    end;
  {$endif}
{$endif}


{---------------------------------------------------------------------------}
procedure SEA_SetFastInit(value: boolean);
  {-set FastInit variable}
begin
  FastInit := value;
end;


{---------------------------------------------------------------------------}
function  SEA_GetFastInit: boolean;
  {-Returns FastInit variable}
begin
  SEA_GetFastInit := FastInit;
end;


{---------------------------------------------------------------------------}
procedure SEA_Reset(var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag}
begin
  with ctx do begin
    bLen :=0;
    Flag :=0;
  end;
end;


{---------------------------------------------------------------------------}
function SEA_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBits: word; var ctx: TSEAContext): integer;
  {-SEED context/round key initialization}
var
  LK: TWA4;
  i,j: integer;
{$ifndef BIT16}
  T: longint;
{$else}
  H: byte;
  B: TSEABlock absolute LK;
{$endif}
begin
  if KeyBits<>128 then begin
    SEA_Init := SEA_Err_Invalid_Key_Size;
    exit;
  end;

  SEA_Init := 0;

  if FastInit then begin
    {Clear only the necessary context data at init. IV and buf}
    {remain uninitialized, other fields are initialized below.}
    SEA_Reset(ctx);
    {$ifdef CONST}
      ctx.IncProc := nil;
    {$else}
      {TP5-6 do not like IncProc := nil;}
      fillchar(ctx.IncProc, sizeof(ctx.IncProc), 0);
    {$endif}
  end
  else fillchar(ctx, sizeof(ctx), 0);

  for i:=0 to 3 do LK[i] := RB(TWA4(Key)[i]);
  j := 0;
  for i:=0 to 15 do begin
    ctx.RK[j] := SG(LK[0]+LK[2]-KC[i]); inc(j);
    ctx.RK[j] := SG(LK[1]-LK[3]+KC[i]); inc(j);
    {$ifndef BIT16}
      if odd(i) then begin
        T := LK[3] shr 24;
        LK[3] := (LK[3] shl 8) or (LK[2] shr 24);
        LK[2] := (LK[2] shl 8) or T;
      end
      else begin
        T := LK[0] and $FF;
        LK[0] := (LK[0] shr 8) or ((LK[1] and $FF) shl 24);
        LK[1] := (LK[1] shr 8) or (T shl 24);
      end
    {$else}
      {for BIT16 use move for 8 bit rotation of 64 bit}
      if odd(i) then begin
        H := B[15];
        move(B[8],B[9],7);
        B[8] := H;
      end
      else begin
        H := B[0];
        move(B[1],B[0],7);
        B[7] := H;
      end;
    {$endif}
  end;
end;


{---------------------------------------------------------------------------}
procedure SEA_Encrypt(var ctx: TSEAContext; {$ifdef CONST} const {$else} var {$endif}  BI: TSEABlock; var BO: TSEABlock);
  {-encrypt one block (in ECB mode)}
var
  T0,T1: longint;
  B: TWA4;
  i,j: integer;
begin
   B[0] := RB(TWA4(BI)[0]);
   B[1] := RB(TWA4(BI)[1]);
   B[2] := RB(TWA4(BI)[2]);
   B[3] := RB(TWA4(BI)[3]);
   with ctx do begin
     j:=0;
     for i:=1 to 8 do begin
       {First part of double round}
       T0 := B[2] xor RK[j];
       T1 := SG(T0 xor B[3] xor RK[j+1]);
       T0 := SG(T1 + T0);
       T1 := SG(T1 + T0);
       B[1] := B[1] xor T1;
       B[0] := B[0] xor (T0 + T1);
       {Second part of double round}
       T0 := B[0] xor RK[j+2];
       T1 := SG(T0 xor B[1] xor RK[j+3]);
       T0 := SG(T1 + T0);
       T1 := SG(T1 + T0);
       B[3] := B[3] xor T1;
       B[2] := B[2] xor (T0 + T1);
       inc(j,4);
     end;
   end;
   TWA4(BO)[0] := RB(B[2]);
   TWA4(BO)[1] := RB(B[3]);
   TWA4(BO)[2] := RB(B[0]);
   TWA4(BO)[3] := RB(B[1]);
end;


{---------------------------------------------------------------------------}
procedure SEA_Decrypt(var ctx: TSEAContext; {$ifdef CONST} const {$else} var {$endif}  BI: TSEABlock; var BO: TSEABlock);
  {-decrypt one block (in ECB mode)}
var
  T0,T1: longint;
  B: TWA4;
  i,j: integer;
begin
   B[0] := RB(TWA4(BI)[0]);
   B[1] := RB(TWA4(BI)[1]);
   B[2] := RB(TWA4(BI)[2]);
   B[3] := RB(TWA4(BI)[3]);
   with ctx do begin
     j := 28;
     for i:=1 to 8 do begin
       {First part of double round}
       T0 := B[2] xor RK[j+2];
       T1 := SG(T0 xor B[3] xor RK[j+3]);
       T0 := SG(T1 + T0);
       T1 := SG(T1 + T0);
       B[1] := B[1] xor T1;
       B[0] := B[0] xor (T0 + T1);
       {Second part of double round}
       T0 := B[0] xor RK[j];
       T1 := SG(T0 xor B[1] xor RK[j+1]);
       T0 := SG(T1 + T0);
       T1 := SG(T1 + T0);
       B[3] := B[3] xor T1;
       B[2] := B[2] xor (T0 + T1);
       dec(j,4);
     end;
   end;
   TWA4(BO)[0] := RB(B[2]);
   TWA4(BO)[1] := RB(B[3]);
   TWA4(BO)[2] := RB(B[0]);
   TWA4(BO)[3] := RB(B[1]);
end;


end.
