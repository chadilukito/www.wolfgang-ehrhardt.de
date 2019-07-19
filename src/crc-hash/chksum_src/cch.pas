program cch;

(*************************************************************************

 DESCRIPTION     :  Console demo for CRC/HASH

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12/D17-D18, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODUS   :  ---

 REFERENCES      :  ---


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     18.03.02  we          D3 demo for DLL
 0.20     06.05.03  we          with units (no DLL), for TP5.5/6/7, D1-D6, FPC
 0.30     12.09.03  we          with Adler32, CRC64
 0.40     05.10.03  we          STD.INC, TP5.0
 0.50     24.10.03  we          speedups
 0.60     30.11.03  we          SHA384/512
 0.62     02.01.04  we          SHA224
 0.63     11.04.04  we          D7, BP7 WIN/DPMI
 0.64     04.01.05  we          recompiled to fix SHA512/384 bug
 0.65     22.05.05  we          $I-, ShareDenyNone for BIT32
 0.70     22.05.05  we          Options
 0.71     02.12.05  we          Bugfix: no confusing NOSHAxxx-defines
 0.72     11.12.05  we          Whirlpool
 0.73     22.01.06  we          New hash units
 0.74     01.02.06  we          RIPEMD-160
 0.75     05.04.06  we          CRC24
 0.76     11.05.06  we          Print "not found" for nonzero findfirst
 0.77     21.01.07  we          Bugfix Whirlpool
 0.78     10.02.07  we          Without filesize
 0.79     21.02.07  we          MD4, ED2K
 0.80     24.02.07  we          eDonkey AND eMule
 0.81     30.09.07  we          Bug fix SHA512/384 for file sizes above 512MB
 0.81.1   03.10.07  we          Run self tests with -t
 0.81.2   15.11.08  we          BTypes, str255, BString
 0.82     21.07.09  we          D12 fixes
 0.83     11.03.12  we          SHA512/224, SHA512/256
 0.84     26.12.12  we          D17 and 64-bit adjustments
 0.85     12.08.15  we          SHA3 algorithms
 0.86     18.05.17  we          Blake2s
 0.87     03.11.17  we          Blake2b
 0.88     24.11.17  we          Blake2b for VER5X

**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2002-2017 Wolfgang Ehrhardt

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

{$ifdef BIT16}
  {$ifdef DPMI}
    {$M $1000}
  {$else}
    {$M $4000,0,655360}
  {$endif}
{$endif}


{$I-,V-}

{$ifndef FPC}
  {$B-,N-}
{$endif}

{$undef UseDOS}

{Check if we can use DOS unit}

{$ifdef MSDOS}
  {$define UseDOS}  {includes FPC Go32V2!}
{$endif}

{$ifdef DPMI}
  {$define UseDOS}
{$endif}

{$ifdef VirtualPascal}
  {$define UseDOS}
{$endif}

{$ifndef UseDOS}
  {$ifdef VER70}
    {BP7Win}
    {$define UseWinDOS}
    {$x+}
  {$endif}
  {$ifdef VER15}
    {$define UseWinDOS}
    {$x+}
  {$endif}
{$endif}


{$ifdef APPCONS}
  {$apptype console}
{$endif}


uses
  {$ifdef WINCRT}
    WinCRT,
  {$endif}

  {$ifdef UseWinDOS}
    WinDOS, Strings,   {BP7Win}
  {$else}
    {$ifdef UseDOS}
      DOS,
    {$else}
      {$ifdef UNIT_SCOPE}
        System.SysUtils,
      {$else}
        SysUtils,
      {$endif}
    {$endif}
  {$endif}
  CRC16, CRC24, CRC32, Adler32, CRC64, hash, MD5, RMD160,
  SHA1, SHA256, SHA224, SHA384, SHA512, SHA5_224, SHA5_256,
  SHA3_224, SHA3_256, SHA3_384, SHA3_512,
  Whirl512,MD4,ED2K,Blaks224, Blaks256, Blakb384, Blakb512,
  BTypes, mem_util;

const
  CCH_Version = '0.88';

{$ifdef J_OPT}
{$J+}
{$endif}

const
  Base64: boolean = false;
  LSB1  : boolean = false;

{$ifdef UseWinDOS}
var
  buf: array[1..$6800] of byte;  {BP7Win: data segment too large!!}
{$else}
{$ifdef VER80}
var
  buf: array[1..$4800] of byte;  {D1: data segment too large!!}
{$else}
var
  buf: array[1..$A000] of byte;
{$endif}
{$endif}


{---------------------------------------------------------------------------}
procedure Process1File({$ifdef CONST} const {$endif} FName: str255);
  {-Process a single file}
var
  {$ifdef MSDOS}
    n: word;
  {$else}
    {$ifdef BIT16}
      n: word;
    {$else}
      n: longint;
    {$endif}
  {$endif}
  CRC16: word;
  CRC24: longint; pgpsig: TPGPDigest;
  CRC32: longint;
  Adler: longint;
  CRC64: TCRC64;
  RMD160Context  : THashContext;    RMD160Digest: TRMD160Digest;
  SHA1Context    : THashContext;      SHA1Digest: TSHA1Digest;
  SHA256Context  : THashContext;    SHA256Digest: TSHA256Digest;
  ED2KContext    : TED2KContext;         ED2KRes: TED2KResult;
  MD4Context     : THashContext;       MD4Digest: TMD4Digest;
  MD5Context     : THashContext;       MD5Digest: TMD5Digest;
  SHA224Context  : THashContext;    SHA224Digest: TSHA224Digest;
  SHA384Context  : THashContext;    SHA384Digest: TSHA384Digest;
  SHA512Context  : THashContext;    SHA512Digest: TSHA512Digest;
  WhirlContext   : THashContext;     WhirlDigest: TWhirlDigest;
  SHA5_224Context: THashContext;  SHA5_224Digest: TSHA5_224Digest;
  SHA5_256Context: THashContext;  SHA5_256Digest: TSHA5_256Digest;
  SHA3_224Context: THashContext;  SHA3_224Digest: TSHA3_224Digest;
  SHA3_256Context: THashContext;  SHA3_256Digest: TSHA3_256Digest;
  SHA3_384Context: THashContext;  SHA3_384Digest: TSHA3_384Digest;
  SHA3_512Context: THashContext;  SHA3_512Digest: TSHA3_512Digest;
  Blaks_224Context: THashContext;  Blaks_224Digest: TBlake2S_224Digest;
  Blaks_256Context: THashContext;  Blaks_256Digest: TBlake2S_256Digest;
  Blakb_384Context: THashContext;  Blakb_384Digest: TBlake2B_384Digest;
  Blakb_512Context: THashContext;  Blakb_512Digest: TBlake2B_512Digest;

  f: file;

  {----------------------------------------------------------------------}
  function RB(A: longint): longint;
    {-rotate byte of longint}
  begin
    RB := (A shr 24) or ((A shr 8) and $FF00) or ((A shl 8) and $FF0000) or (A shl 24);
  end;

  {----------------------------------------------------------------------}
  function OutStr(psrc: pointer; L: integer): BString;
    {-Format string as hex or base64}
  begin
    if Base64 then OutStr := Base64Str(psrc, L)
    else OutStr := HexStr(psrc, L)
  end;

begin
  {$ifdef bit32}
    {ShareDenyNone to avoid error if redirected output is processed}
    FileMode := $40;
  {$else}
    FileMode := $0;
  {$endif}
  writeln(Fname);

  system.assign(f,{$ifdef D12Plus} string {$endif}(FName));
  system.reset(f,1);
  if IOresult<>0 then begin
    writeln('*** could not be opened');
    exit;
  end;

  RMD160Init(RMD160Context);
  SHA1Init(SHA1Context);
  SHA256Init(SHA256Context);
  SHA224Init(SHA224Context);
  SHA384Init(SHA384Context);
  SHA512Init(SHA512Context);
  SHA5_224Init(SHA5_224Context);
  SHA5_256Init(SHA5_256Context);
  SHA3_224Init(SHA3_224Context);
  SHA3_256Init(SHA3_256Context);
  SHA3_384Init(SHA3_384Context);
  SHA3_512Init(SHA3_512Context);
  Blaks224Init(Blaks_224Context);
  Blaks256Init(Blaks_256Context);
  Blakb384Init(Blakb_384Context);
  Blakb512Init(Blakb_512Context);
  Whirl_Init(WhirlContext);
  ED2K_Init(ED2KContext);
  MD4Init(MD4Context);
  MD5Init(MD5Context);
  CRC16Init(CRC16);
  CRC24Init(CRC24);
  CRC32Init(CRC32);
  Adler32Init(adler);
  CRC64Init(CRC64);

  repeat
    blockread(f,buf,sizeof(buf),n);
    if IOResult<>0 then begin
      writeln('*** read error');
      {$ifdef CONST}
        break;
      {$else}
        {Trick V5.5/6.0, no break for VER < 7}
        n := 0;
      {$endif}
    end;
    if n<>0 then begin
      RMD160Update(RMD160Context,@buf,n);
      SHA1Update(SHA1Context,@buf,n);
      ED2K_Update(ED2KContext,@buf,n);
      MD4Update(MD4Context,@buf,n);
      MD5Update(MD5Context,@buf,n);
      Adler32Update(adler,@buf,n);
      CRC16Update(CRC16,@buf,n);
      CRC24Update(CRC24,@buf,n);
      CRC32Update(CRC32,@buf,n);
      CRC64Update(CRC64,@buf,n);
      SHA224Update(SHA224Context,@buf,n);
      SHA256Update(SHA256Context,@buf,n);
      SHA384Update(SHA384Context,@buf,n);
      SHA512Update(SHA512Context,@buf,n);
      SHA5_224Update(SHA5_224Context,@buf,n);
      SHA5_256Update(SHA5_256Context,@buf,n);
      Whirl_Update(WhirlContext,@buf,n);
      SHA3_224Update(SHA3_224Context,@buf,n);
      SHA3_256Update(SHA3_256Context,@buf,n);
      SHA3_384Update(SHA3_384Context,@buf,n);
      SHA3_512Update(SHA3_512Context,@buf,n);
      Blaks224Update(Blaks_224Context,@buf,n);
      Blaks256Update(Blaks_256Context,@buf,n);
      Blakb384Update(Blakb_384Context,@buf,n);
      Blakb512Update(Blakb_512Context,@buf,n);
    end;
  until n<>sizeof(buf);

  system.close(f);
  n := IOResult;

  RMD160Final(RMD160Context,RMD160Digest);
  SHA1Final(SHA1Context,SHA1Digest);
  ED2K_Final(ED2KContext,ED2KRes);
  MD4Final(MD4Context,MD4Digest);
  MD5Final(MD5Context,MD5Digest);
  CRC16Final(CRC16);
  CRC24Final(CRC24);
  CRC32Final(CRC32);
  Adler32Final(adler);
  CRC64Final(CRC64);
  SHA224Final(SHA224Context,SHA224Digest);
  SHA256Final(SHA256Context,SHA256Digest);
  SHA384Final(SHA384Context,SHA384Digest);
  SHA512Final(SHA512Context,SHA512Digest);
  SHA5_224Final(SHA5_224Context,SHA5_224Digest);
  SHA5_256Final(SHA5_256Context,SHA5_256Digest);
  Whirl_Final(WhirlContext,WhirlDigest);
  SHA3_224Final(SHA3_224Context,SHA3_224Digest);
  SHA3_256Final(SHA3_256Context,SHA3_256Digest);
  SHA3_384Final(SHA3_384Context,SHA3_384Digest);
  SHA3_512Final(SHA3_512Context,SHA3_512Digest);
  Blaks224Final(Blaks_224Context,Blaks_224Digest);
  Blaks256Final(Blaks_256Context,Blaks_256Digest);
  Blakb384Final(Blakb_384Context,Blakb_384Digest);
  Blakb512Final(Blakb_512Context,Blakb_512Digest);

  if (not LSB1) and (not Base64) then begin
    {swap bytes: display shall look like word / longint}
    {but HexStr constructs LSB first}
    CRC16 := swap(CRC16);
    CRC32 := RB(CRC32);
    Adler := RB(Adler);
  end;

  Long2PGP(CRC24, pgpsig);

  writeln('      CRC16: '+OutStr(@CRC16, sizeof(CRC16)));

  {special case 3 byte CRC24 use CRC24 variable or pgpsig}
  if LSB1 then writeln('      CRC24: '+OutStr(@CRC24, 3))
  else writeln('      CRC24: '+OutStr(@pgpsig, 3));

  writeln('      CRC32: '+OutStr(@CRC32, sizeof(CRC32)));
  writeln('    Adler32: '+OutStr(@adler, sizeof(adler)));
  writeln('      CRC64: '+OutStr(@CRC64, sizeof(CRC64)));
  writeln('    eDonkey: '+OutStr(@ED2KRes.eDonkey, sizeof(ED2KRes.eDonkey)));
 if ED2KRes.differ then begin
  writeln('      eMule: '+OutStr(@ED2KRes.eMule, sizeof(ED2KRes.eMule)));
 end;
  writeln('        MD4: '+OutStr(@MD4Digest, sizeof(MD4Digest)));
  writeln('        MD5: '+OutStr(@MD5Digest, sizeof(MD5Digest)));
  writeln('  RIPEMD160: '+OutStr(@RMD160Digest, sizeof(RMD160Digest)));
  writeln('       SHA1: '+OutStr(@SHA1Digest, sizeof(SHA1Digest)));
  writeln('     SHA224: '+OutStr(@SHA224Digest, sizeof(SHA224Digest)));
  writeln('     SHA256: '+OutStr(@SHA256Digest, sizeof(SHA256Digest)));
  writeln('     SHA384: '+OutStr(@SHA384Digest, sizeof(SHA384Digest)));
  writeln('     SHA512: '+OutStr(@SHA512Digest, sizeof(SHA512Digest)));
  writeln(' SHA512/224: '+OutStr(@SHA5_224Digest,sizeof(SHA5_224Digest)));
  writeln(' SHA512/256: '+OutStr(@SHA5_256Digest,sizeof(SHA5_256Digest)));
  writeln('  Whirlpool: '+OutStr(@WhirlDigest, sizeof(WhirlDigest)));
  writeln('   SHA3-224: '+OutStr(@SHA3_224Digest, sizeof(SHA3_224Digest)));
  writeln('   SHA3-256: '+OutStr(@SHA3_256Digest, sizeof(SHA3_256Digest)));
  writeln('   SHA3-384: '+OutStr(@SHA3_384Digest, sizeof(SHA3_384Digest)));
  writeln('   SHA3-512: '+OutStr(@SHA3_512Digest, sizeof(SHA3_512Digest)));
  writeln('Blake2s-224: '+OutStr(@Blaks_224Digest, sizeof(Blaks_224Digest)));
  writeln('Blake2s-256: '+OutStr(@Blaks_256Digest, sizeof(Blaks_256Digest)));
  writeln('Blake2b-384: '+OutStr(@Blakb_384Digest, sizeof(Blakb_384Digest)));
  writeln('Blake2b-512: '+OutStr(@Blakb_512Digest, sizeof(Blakb_512Digest)));
  writeln;
end;


{$ifdef UseWinDOS}

{---------------------------------------------------------------------------}
procedure ProcessFile({$ifdef CONST} const {$endif} s: str255);
  {-Process one cmd line paramater, wildcards allowed}
var
  SR: TSearchRec;
  Path: array[0..sizeof(str255)+1] of Char8;
  base: array[0..fsDirectory] of Char8;
  Name: array[0..fsFileName] of Char8;
  Ext: array[0..fsExtension] of Char8;
begin
  StrPCopy(Path,s);
  FileSplit(Path,base,name,ext);
  FindFirst(Path, faAnyFile, SR);
  if DosError<>0 then writeln('*** not found: ',s);
  while DosError=0 do begin
    if SR.Attr and  (faVolumeID or faDirectory) = 0 then begin
      Process1File(StrPas(Base)+StrPas(SR.Name));
    end;
    FindNext(SR);
  end;
end;

{$else}

{$ifdef UseDOS}

{---------------------------------------------------------------------------}
procedure ProcessFile({$ifdef CONST} const {$endif} s: str255);
  {-Process one cmd line parameter, wildcards allowed}
var
  SR: SearchRec;
  n: namestr;
  e: extstr;
  base: str255;
begin
  FSplit(s,base,n,e);
  FindFirst(s, AnyFile, SR);
  if DosError<>0 then writeln('*** not found: ',s);
  while DosError=0 do begin
    if SR.Attr and  (VolumeID or Directory) = 0 then begin
      Process1File(Base+SR.Name);
    end;
    FindNext(SR);
  end;
end;

{$else}


{$ifdef D12Plus}

{---------------------------------------------------------------------------}
procedure ProcessFile(const s: string);
  {-Process one cmd line parameter, wildcards allowed}
var
  SR: TSearchRec;
  FR: integer;
  base: string;
begin
  Base := ExtractFilePath(s);
  FR := FindFirst(s, faAnyFile, SR);
  if FR<>0 then writeln('*** not found: ',s);
  while FR=0 do begin
    if SR.Attr and  (faVolumeID or faDirectory) = 0 then begin
      Process1File(str255(Base+SR.Name));
    end;
    FR := FindNext(SR);
  end;
  FindClose(SR);
end;

{$else}

{---------------------------------------------------------------------------}
procedure ProcessFile(const s: str255);
  {-Process one cmd line parameter, wildcards allowed}
var
  SR: TSearchRec;
  FR: integer;
  base: str255;
begin
  Base := ExtractFilePath(s);
  FR := FindFirst(s, faAnyFile, SR);
  if FR<>0 then writeln('*** not found: ',s);
  while FR=0 do begin
    {$ifdef FPC}
     {suppress warnings for faVolumeID}
     {$WARN SYMBOL_DEPRECATED OFF}
     {$WARN SYMBOL_PLATFORM OFF}
    {$endif}
    if SR.Attr and  (faVolumeID or faDirectory) = 0 then begin
      Process1File(Base+SR.Name);
    end;
    FR := FindNext(SR);
  end;
  FindClose(SR);
end;
{$endif}

{$endif}

{$endif}


{---------------------------------------------------------------------------}
procedure Selftests;
  {-Self test of all check sum algorithms}
  procedure report(aname: str255; passed: boolean);
  begin
    writeln(' ',aname, ' self test passed: ',passed);
  end;
begin
  report('CRC16      ', CRC16SelfTest   );
  report('CRC24      ', CRC24SelfTest   );
  report('CRC32      ', CRC32SelfTest   );
  report('Adler32    ', Adler32SelfTest );
  report('CRC64      ', CRC64SelfTest   );
  report('eDonkey    ', ED2K_SelfTest   );
  report('MD4        ', MD4SelfTest     );
  report('MD5        ', MD5SelfTest     );
  report('RIPEMD160  ', RMD160SelfTest  );
  report('SHA1       ', SHA1SelfTest    );
  report('SHA224     ', SHA224SelfTest  );
  report('SHA256     ', SHA256SelfTest  );
  report('SHA384     ', SHA384SelfTest  );
  report('SHA512     ', SHA512SelfTest  );
  report('SHA512/224 ', SHA5_224SelfTest);
  report('SHA512/256 ', SHA5_256SelfTest);
  report('Whirlpool  ', Whirl_SelfTest  );
  report('SHA3-224   ', SHA3_224SelfTest);
  report('SHA3-256   ', SHA3_256SelfTest);
  report('SHA3-384   ', SHA3_384SelfTest);
  report('SHA3-512   ', SHA3_512SelfTest);
  report('Blake2s-224', Blaks224SelfTest);
  report('Blake2s-256', Blaks256SelfTest);
  report('Blake2b-384', Blakb384SelfTest);
  report('Blake2b-512', Blakb512SelfTest);
end;


{---------------------------------------------------------------------------}
procedure usage;
begin
  writeln('Usage: CCH [arg1] ... [argN]');
  writeln(' args may be file specs (wildcards allowed) or options');
  writeln('  -b: display results in Base64');
  writeln('  -h: display in hex (default)');
  writeln('  -u: display in HEX');
  writeln('  -l: display CRC16/24/32,Adler LSB first');
  writeln('  -t: run self tests of algorithms');
  writeln('  -m: display CRC16/24/32,Adler MSB first (default)');
  writeln('  -?: this help');
  halt;
end;


{---------------------------------------------------------------------------}
var
  i,k,n: integer;
  {$ifdef D12Plus}
    s: string;
  {$else}
    s: string[2];
  {$endif}
begin
  writeln('CCH V', CCH_Version, '  -  Calculate CRC/Hash   (c) 2002-2017 W.Ehrhardt');
  n := 0;
  for i:=1 to Paramcount do begin
    s := Paramstr(i);
    for k:=1 to length(s) do s[k] := upcase(s[k]);
    if s='-B' then Base64 := true
    else if s='-T' then begin
      Selftests;
      inc(n);
    end
    else if s='-H'then begin
      Base64 := false;
      HexUpper := false;
    end
    else if s='-U'then begin
      Base64 := false;
      HexUpper := true;
    end
    else if s='-L'then LSB1 := true
    else if s='-M'then LSB1 := false
    else if s[1]='-'then usage
    else begin
      ProcessFile(paramstr(i));
      inc(n);
    end;
  end;
  if n=0 then usage;
end.
