unit ZLibH;

{we: ZLIB (functions), ZLIBH(types/consts), GZIO(gz functions)
     should be the only units USED by applications of zlib}

(************************************************************************
  zlibh -- types/consts of the 'zlib' general purpose compression library
  version 1.1.4, March 11th, 2002

  Copyright (C) 1995-2002 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu


  The data format used by the zlib library is described by RFCs (Request for
  Comments) 1950 to 1952 in the files ftp://ds.internic.net/rfc/rfc1950.txt
  (zlib format), rfc1951.txt (deflate format) and rfc1952.txt (gzip format).

  Parts of Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali

  ------------------------------------------------------------------------
  Modification/Pascal translation by W.Ehrhardt:

  Aug 2000
    - ZLIB 113 changes
  Feb 2002
    - Source code reformating/reordering
    - make code work under BP7/DPMI&Win
  Mar 2002
    - ZLIB 114 changes
  Apr 2004
    - procedure z_assign(var f: file; p: PChar): workaround for Delphi6/7 bug
  Mar 2005
    - Code cleanup for WWW upload
  May 2005
    - Assert moved from zutil (ease of use if no system.assert)
  Jul 2008
    - update uInt/uLong for FPC2
  Jul 2009
    - D12 fixes
  Sep 2015
    - FPC 3
------------------------------------------------------------------------

*************************************************************************)

interface

{$x+}

{$i zconf.inc}

{type declarations}
type
  Bytef  = byte;
  charf  = byte;

  str255 = string[255];

  {$ifdef unicode}
    Char8  = AnsiChar;
    PChar8 = PAnsiChar;
  {$else}
    Char8  = Char;
    PChar8 = PChar;
  {$endif}

  {$ifdef VER70}
    int    = integer;
  {$else}
    int    = longint;
  {$endif}

  intf   = int;
  {$ifdef MSDOS}
    uInt   = word;
  {$else}
    {$ifdef FPC}
      {$ifndef VER1}         {Sep 2015}
        uInt   = cardinal;
      {$else}
        uInt   = longint;
      {$endif}
    {$else}
      {$ifdef VER70}
        uInt   = word;       {*we 0202: BP7/Win}
      {$else}
        uInt   = cardinal;   {16 bits or more}
      {$endif}
    {$endif}
  {$endif}
  uIntf  = uInt;

  Long   = longint;
  {$ifdef FPC}
    {$ifdef VER1}            {Sep 2015}
      uLong   = longint;
    {$else}
      uLong   = cardinal;
    {$endif}
  {$else}
    {$ifdef D4Plus}
      uLong  = Cardinal;
    {$else}
      {$ifdef ver120}
        uLong  = Cardinal;
      {$else}
        uLong  = longint;    {32 bits or more}
      {$endif}
    {$endif}
  {$endif}


  uLongf = uLong;

  voidp  = pointer;
  voidpf = voidp;
  pBytef = ^Bytef;
  puIntf = ^uIntf;
  puLong = ^uLongf;

  {$ifdef FPC}               {Sep 2015}
    {$ifdef VER1}
      ptr2int = uInt;
    {$else}
      ptr2int = PtrUInt;
    {$endif}
  {$else}
    ptr2int = uInt;
  {$endif}
  {a pointer to integer casting is used to do pointer arithmetic.
  ptr2int must be an integer type and sizeof(ptr2int) must be less
  than sizeof(pointer) - Nomssi}



{The memory requirements for deflate are (in bytes):

  1 shl (windowBits+2)   +  1 shl (memLevel+9)

that is: 128K for windowBits=15  +  128K for memLevel = 8  (default values)
plus a few kilobytes for small objects. For example, if you want to reduce
the default memory requirements from 256K to 128K, compile with

DMAX_WBITS=14
DMAX_MEM_LEVEL=7

Of course this will generally degrade compression (there's no free lunch).

The memory requirements for inflate are (in bytes)

1 shl windowBits

that is, 32K for windowBits=15 (default value) plus a few kilobytes
for small objects.}

{Compile with -DMAXSEG_64K if the alloc function cannot allocate more
than 64k bytes at a time (needed on systems with 16-bit int).}

const
  {$ifdef MAXSEG_64K}
    MaxMemBlock = $FFFF;
  {$else}
    MaxMemBlock = MaxInt;
  {$endif}

  {Maximum value for memLevel in deflateInit2}
  {$ifdef MAXSEG_64K}
    {$ifdef VER70}
      MAX_MEM_LEVEL = 7;
      DEF_MEM_LEVEL = MAX_MEM_LEVEL;  {default memLevel}
    {$else}
      MAX_MEM_LEVEL = 8;
      DEF_MEM_LEVEL = MAX_MEM_LEVEL;  {default memLevel}
    {$endif}
  {$else}
    MAX_MEM_LEVEL = 9;
    DEF_MEM_LEVEL = 8; {if MAX_MEM_LEVEL > 8}
  {$endif}

  {Maximum value for windowBits in deflateInit2 and inflateInit2}
  {$ifdef VER70}
    MAX_WBITS = 15; {32K LZ77 window}  {*we W0800}
  {$else}
    MAX_WBITS = 15; {32K LZ77 window}
  {$endif}

  {default windowBits for decompression. MAX_WBITS is for compression only}
  {$ifdef VER70}
    DEF_WBITS = 15;  {*we W0800, with MAX_BITS = 14 some files could not be}
                     {decompressed with VER70, cf. Memory Footprint in zlib_tech.html}
  {$else}
    DEF_WBITS = MAX_WBITS;
  {$endif}



type
  uch  = byte;
  uchf = uch;
  ush  = word;
  ushf = ush;
  ulg  = longint;

  unsigned = uInt;

  pcharf = ^charf;
  pushf  = ^ushf;

type
  zByteArray = array[0..(MaxMemBlock div sizeof(Bytef))-1] of Bytef;
  pzByteArray = ^zByteArray;

type
  zIntfArray  = array[0..(MaxMemBlock div sizeof(Intf))-1] of Intf;
  pzIntfArray = ^zIntfArray;


type
  alloc_func = function(opaque: voidpf; items: uInt; size: uInt): voidpf;
  free_func  = procedure(opaque: voidpf; address: voidpf);

type
  z_streamp= ^z_stream;
  z_stream = record
    next_in  : pBytef;      {next input byte}
    avail_in : uInt;        {number of bytes available at next_in}
    total_in : uLong;       {total nb of input bytes read so far}
    next_out : pBytef;      {next output byte should be put there}
    avail_out: uInt;        {remaining free space at next_out}
    total_out: uLong;       {total nb of bytes output so far}
    msg      : string[255]; {last error message, '' if no error}
    state    : pointer;     {internal state:  not visible by applications}
    zalloc   : alloc_func;  {used to allocate the internal state}
    zfree    : free_func;   {used to free the internal state}
    opaque   : voidpf;      {private data object passed to zalloc and zfree}
    data_type: int;         {best guess about the data type: ascii or binary}
    adler    : uLong;       {adler32 value of the uncompressed data}
    reserved : uLong;       {reserved for future use}
  end;


{ The application must update next_in and avail_in when avail_in has
  dropped to zero. It must update next_out and avail_out when avail_out
  has dropped to zero. The application must initialize zalloc, zfree and
  opaque before calling the init function. All other fields are set by the
  compression library and must not be updated by the application.

  The opaque value provided by the application will be passed as the first
  parameter for calls of zalloc and zfree. This can be useful for custom
  memory management. The compression library attaches no meaning to the
  opaque value.

  zalloc must return Z_NULL if there is not enough memory for the object.
  On 16-bit systems, the functions zalloc and zfree must be able to allocate
  exactly 65536 bytes, but will not be required to allocate more than this
  if the symbol MAXSEG_64K is defined (see zconf.h). WARNING: On MSDOS,
  pointers returned by zalloc for objects of exactly 65536 bytes *must*
  have their offset normalized to zero. The default allocation function
  provided by this library ensures this (see zutil.c). To reduce memory
  requirements and avoid any allocation of 64K objects, at the expense of
  compression ratio, compile the library with -DMAX_WBITS=14 (see zconf.h).

  The fields total_in and total_out can be used for statistics or
  progress reports. After compression, total_in holds the total size of
  the uncompressed data and may be saved for use in the decompressor
  (particularly if the decompressor wants to decompress everything in
  a single step).}

const
  {Allowed flush values; see deflate() below for details}
  Z_NO_FLUSH      = 0;
  Z_PARTIAL_FLUSH = 1;
  Z_SYNC_FLUSH    = 2;
  Z_FULL_FLUSH    = 3;
  Z_FINISH        = 4;

  {Return codes for the compression/decompression functions. Negative
  values are errors, positive values are used for special but normal events.}
  Z_OK            = 0;
  Z_STREAM_END    = 1;
  Z_NEED_DICT     = 2;
  Z_ERRNO         = (-1);
  Z_STREAM_ERROR  = (-2);
  Z_DATA_ERROR    = (-3);
  Z_MEM_ERROR     = (-4);
  Z_BUF_ERROR     = (-5);
  Z_VERSION_ERROR = (-6);

  {compression levels}
  Z_NO_COMPRESSION         = 0;
  Z_BEST_SPEED             = 1;
  Z_BEST_COMPRESSION       = 9;
  Z_DEFAULT_COMPRESSION    = (-1);

  {compression strategy; see deflateInit2() below for details}
  Z_FILTERED            = 1;
  Z_HUFFMAN_ONLY        = 2;
  Z_DEFAULT_STRATEGY    = 0;

  {Possible values of the data_type field}
  Z_BINARY   = 0;
  Z_ASCII    = 1;
  Z_UNKNOWN  = 2;

  {The deflate compression method (the only one supported in this version)}
  Z_DEFLATED   = 8;

  {for initializing zalloc, zfree, opaque}
  Z_NULL  = nil;


{common constants}
const
  {The three kinds of block type}
  STORED_BLOCK = 0;
  STATIC_TREES = 1;
  DYN_TREES = 2;

const
  {The minimum and maximum match lengths}
  MIN_MATCH = 3;
  {$ifdef MAX_MATCH_IS_258}
    MAX_MATCH = 258;
  {$else}
    MAX_MATCH = ??;    {deliberate syntax error}
  {$endif}

const
  {preset dictionary flag in zlib header}
  PRESET_DICT = $20;


const
  ZLIB_VERSION: string[10] = '1.1.4';
  inflate_copyright: string[60] = ' inflate 1.1.4 Copyright 1995-2002 Mark Adler';

 {If you use the zlib library in a product, an acknowledgment is welcome
  in the documentation of your product. If for some reason you cannot
  include such an acknowledgment, I would appreciate that you keep this
  copyright string in the executable of your product.}

const
  z_errbase = Z_NEED_DICT;
  z_errmsg  : array[0..9] of string[21] = {indexed by 2-zlib_error}
                ('need dictionary',     {Z_NEED_DICT       2 }
                 'stream end',          {Z_STREAM_END      1 }
                 '',                    {Z_OK              0 }
                 'file error',          {Z_ERRNO         (-1)}
                 'stream error',        {Z_STREAM_ERROR  (-2)}
                 'data error',          {Z_DATA_ERROR    (-3)}
                 'insufficient memory', {Z_MEM_ERROR     (-4)}
                 'buffer error',        {Z_BUF_ERROR     (-5)}
                 'incompatible version',{Z_VERSION_ERROR (-6)}
                 '');
const
  z_verbose : int = 1;


procedure z_assign(var f: file; p: PChar8);
  {-workaround for Delphi 6/7 bug}

{$ifdef debug}
{$ifndef HaveAssert}
procedure Assert(cond: boolean; const msg: string);
  {-Assert for Pascal without system.assert}
{$endif}
{$endif}


implementation


{$ifdef debug}
{$ifndef HaveAssert}
{---------------------------------------------------------------------------}
procedure Assert(cond: boolean; const msg: string);
  {-Assert for Pascal without system.assert}
begin
  if not cond then begin
    writeln('zlib assertion failed: ', msg);
    halt(1);
  end;
end;
{$endif}
{$endif}




{$ifdef CONDITIONALEXPRESSIONS}  {D6+}
{---------------------------------------------------------------------------}
procedure z_assign(var f: file; p: PChar8);
  {-workaround for Delphi 6/7/? bug}
begin
  {$ifdef UNICODE}  {D12+}
    assignfile(f,string(p));
  {$else}
    assignfile(f,ansistring(p));
  {$endif}
end;
{$else}

{---------------------------------------------------------------------------}
procedure z_assign(var f: file; p: PChar8);
begin
  system.assign(f,p);
end;
{$endif}

begin
  if length(ZLIB_VERSION)+length(inflate_copyright)=0 then ;  {only for referencing}
end.
