unit Adler;

(************************************************************************
  adler32.c -- compute the Adler-32 checksum of a data stream
  Copyright (C) 1995-1998 Mark Adler

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Feb 2002
    - replaced inner while loop with for
    - Source code reformating/reordering
  Mar 2005
    - Code cleanup for WWW upload
  ------------------------------------------------------------------------

*************************************************************************)


interface


uses
  zlibh;


function adler32(adler: uLong; buf: pBytef; len: uInt): uLong;
  {-Update a running Adler-32 checksum with the bytes buf[0..len-1] and
   return the updated checksum. If buf is nil, this function returns
   the required initial value for the checksum.
   An Adler-32 checksum is almost as reliable as a CRC32 but can be computed
   much faster. Usage example:

   var
     adler: uLong;
   begin
     adler := adler32(0, Z_NULL, 0);
     while read_buffer(buf, len)<>EOF do adler := adler32(adler, buf, len);
     if adler<>original_adler then error();
   end;}

implementation

const
  BASE = uLong(65521); {largest prime smaller than 65536}

  NMAX = 3854;         {value for signed 32 bit integer}
  {NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^31-1}

  {NMAX = 5552; original value for unsigned 32 bit integer}
  {The penalty is the time loss in the extra mod-calls.}



{---------------------------------------------------------------------------}
function adler32(adler: uLong; buf: pBytef; len: uInt): uLong;
  {-Update a running Adler-32 checksum with the bytes buf[0..len-1]}
var
  s1, s2: uLong;
  i,k: int;
begin
  s1 := adler and $ffff;
  s2 := (adler shr 16) and $ffff;

  if not Assigned(buf) then begin
    adler32 := uLong(1);
    exit;
  end;

  while len>0 do begin
    if len<NMAX then k := len else k := NMAX;
    dec(len, k);
    for i:=1 to k do begin
      inc(s1, buf^);
      inc(s2, s1);
      inc(buf);
    end;
    s1 := s1 mod BASE;
    s2 := s2 mod BASE;
  end;
  adler32 := (s2 shl 16) or s1;
end;

end.

