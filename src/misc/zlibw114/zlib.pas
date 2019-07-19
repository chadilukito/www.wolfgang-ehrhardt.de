unit ZLib;

{we: ZLIB (functions), ZLIBH(types/consts), GZIO(gz functions)
     should be the only units USED by applications of zlib}

(************************************************************************
  zlib -- interface of the 'zlib' general purpose compression library
  version 1.1.3, July 9th, 1998

  Copyright (C) 1995-1998 Jean-loup Gailly and Mark Adler

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
  Mar 2005
    - Code cleanup for WWW upload
  Jul 2009
    - D12 fixes
  ------------------------------------------------------------------------

*************************************************************************)

{$x+}

interface


uses ZlibH;


(***************************************************************************)
(*************************  Basic functions  *******************************)
(***************************************************************************)

function deflateInit(var strm: z_stream; level: int): int;
  {Initializes the internal stream state for compression. The fields
  zalloc, zfree and opaque must be initialized before by the caller.
  If zalloc and zfree are set to Z_NULL, deflateInit updates them to
  use default allocation functions.

    The compression level must be Z_DEFAULT_COMPRESSION, or between 0 and 9:
  1 gives best speed, 9 gives best compression, 0 gives no compression at
  all (the input data is simply copied a block at a time).
  Z_DEFAULT_COMPRESSION requests a default compromise between speed and
  compression (currently equivalent to level 6).

    deflateInit returns Z_OK if success, Z_MEM_ERROR if there was not
  enough memory, Z_STREAM_ERROR if level is not a valid compression level,
  Z_VERSION_ERROR if the zlib library version (zlib_version) is incompatible
  with the version assumed by the caller (ZLIB_VERSION).
  msg is set to null if there is no error message.  deflateInit does not
  perform any compression: this will be done by deflate().}


function deflate(var strm: z_stream; flush: int): int;
  {Performs one or both of the following actions:

  - Compress more input starting at next_in and update next_in and avail_in
    accordingly. If not all input can be processed (because there is not
    enough room in the output buffer), next_in and avail_in are updated and
    processing will resume at this point for the next call of deflate().

  - Provide more output starting at next_out and update next_out and avail_out
    accordingly. This action is forced if the parameter flush is non zero.
    Forcing flush frequently degrades the compression ratio, so this parameter
    should be set only when necessary (in interactive applications).
    Some output may be provided even if flush is not set.

  Before the call of deflate(), the application should ensure that at least
  one of the actions is possible, by providing more input and/or consuming
  more output, and updating avail_in or avail_out accordingly; avail_out
  should never be zero before the call. The application can consume the
  compressed output when it wants, for example when the output buffer is full
  (avail_out == 0), or after each call of deflate(). If deflate returns Z_OK
  and with zero avail_out, it must be called again after making room in the
  output buffer because there might be more output pending.

    If the parameter flush is set to Z_PARTIAL_FLUSH, the current compression
  block is terminated and flushed to the output buffer so that the
  decompressor can get all input data available so far. For method 9, a future
  variant on method 8, the current block will be flushed but not terminated.
  Z_SYNC_FLUSH has the same effect as partial flush except that the compressed
  output is byte aligned (the compressor can clear its internal bit buffer)
  and the current block is always terminated; this can be useful if the
  compressor has to be restarted from scratch after an interruption (in which
  case the internal state of the compressor may be lost).
    If flush is set to Z_FULL_FLUSH, the compression block is terminated, a
  special marker is output and the compression dictionary is discarded; this
  is useful to allow the decompressor to synchronize if one compressed block
  has been damaged (see inflateSync below).  Flushing degrades compression and
  so should be used only when necessary.  Using Z_FULL_FLUSH too often can
  seriously degrade the compression. If deflate returns with avail_out == 0,
  this function must be called again with the same value of the flush
  parameter and more output space (updated avail_out), until the flush is
  complete (deflate returns with non-zero avail_out).

    If the parameter flush is set to Z_FINISH, all pending input is processed,
  all pending output is flushed and deflate returns with Z_STREAM_END if there
  was enough output space; if deflate returns with Z_OK, this function must be
  called again with Z_FINISH and more output space (updated avail_out) but no
  more input data, until it returns with Z_STREAM_END or an error. After
  deflate has returned Z_STREAM_END, the only possible operations on the
  stream are deflateReset or deflateEnd.

    Z_FINISH can be used immediately after deflateInit if all the compression
  is to be done in a single step. In this case, avail_out must be at least
  0.1% larger than avail_in plus 12 bytes.  If deflate does not return
  Z_STREAM_END, then it must be called again as described above.

    deflate() may update data_type if it can make a good guess about
  the input data type (Z_ASCII or Z_BINARY). In doubt, the data is considered
  binary. This field is only for information purposes and does not affect
  the compression algorithm in any manner.

    deflate() returns Z_OK if some progress has been made (more input
  processed or more output produced), Z_STREAM_END if all input has been
  consumed and all output has been produced (only when flush is set to
  Z_FINISH), Z_STREAM_ERROR if the stream state was inconsistent (for example
  if next_in or next_out was NULL), Z_BUF_ERROR if no progress is possible.}


function deflateEnd(var strm: z_stream): int;
  {All dynamically allocated data structures for this stream are freed.
  This function discards any unprocessed input and does not flush any
  pending output.

    deflateEnd returns Z_OK if success, Z_STREAM_ERROR if the
  stream state was inconsistent, Z_DATA_ERROR if the stream was freed
  prematurely (some input or output was discarded). In the error case,
  msg may be set but then points to a static string (which must not be
  deallocated).}

function inflateInit(var z: z_stream): int;
  {Initializes the internal stream state for decompression. The fields
  zalloc, zfree and opaque must be initialized before by the caller.  If
  zalloc and zfree are set to Z_NULL, inflateInit updates them to use default
  allocation functions.

    inflateInit returns Z_OK if success, Z_MEM_ERROR if there was not
  enough memory, Z_VERSION_ERROR if the zlib library version is incompatible
  with the version assumed by the caller.  msg is set to null if there is no
  error message. inflateInit does not perform any decompression: this will be
  done by inflate().}

function inflate(var z: z_stream; f: int): int;
  {inflate decompresses as much data as possible, and stops when the input
  buffer becomes empty or the output buffer becomes full. It may introduce
  some output latency (reading input without producing any output)
  except when forced to flush.

  The detailed semantics are as follows. inflate performs one or both of the
  following actions:

  - Decompress more input starting at next_in and update next_in and avail_in
    accordingly. If not all input can be processed (because there is not
    enough room in the output buffer), next_in is updated and processing
    will resume at this point for the next call of inflate().

  - Provide more output starting at next_out and update next_out and avail_out
    accordingly.  inflate() provides as much output as possible, until there
    is no more input data or no more space in the output buffer (see below
    about the flush parameter).

  Before the call of inflate(), the application should ensure that at least
  one of the actions is possible, by providing more input and/or consuming
  more output, and updating the next_* and avail_* values accordingly.
  The application can consume the uncompressed output when it wants, for
  example when the output buffer is full (avail_out == 0), or after each
  call of inflate(). If inflate returns Z_OK and with zero avail_out, it
  must be called again after making room in the output buffer because there
  might be more output pending.

    If the parameter flush is set to Z_SYNC_FLUSH, inflate flushes as much
  output as possible to the output buffer. The flushing behavior of inflate is
  not specified for values of the flush parameter other than Z_SYNC_FLUSH
  and Z_FINISH, but the current implementation actually flushes as much output
  as possible anyway.

    inflate() should normally be called until it returns Z_STREAM_END or an
  error. However if all decompression is to be performed in a single step
  (a single call of inflate), the parameter flush should be set to
  Z_FINISH. In this case all pending input is processed and all pending
  output is flushed; avail_out must be large enough to hold all the
  uncompressed data. (The size of the uncompressed data may have been saved
  by the compressor for this purpose.) The next operation on this stream must
  be inflateEnd to deallocate the decompression state. The use of Z_FINISH
  is never required, but can be used to inform inflate that a faster routine
  may be used for the single inflate() call.

     If a preset dictionary is needed at this point (see inflateSetDictionary
  below), inflate sets strm-adler to the adler32 checksum of the
  dictionary chosen by the compressor and returns Z_NEED_DICT; otherwise
  it sets strm->adler to the adler32 checksum of all output produced
  so far (that is, total_out bytes) and returns Z_OK, Z_STREAM_END or
  an error code as described below. At the end of the stream, inflate()
  checks that its computed adler32 checksum is equal to that saved by the
  compressor and returns Z_STREAM_END only if the checksum is correct.

    inflate() returns Z_OK if some progress has been made (more input processed
  or more output produced), Z_STREAM_END if the end of the compressed data has
  been reached and all uncompressed output has been produced, Z_NEED_DICT if a
  preset dictionary is needed at this point, Z_DATA_ERROR if the input data was
  corrupted (input stream not conforming to the zlib format or incorrect
  adler32 checksum), Z_STREAM_ERROR if the stream structure was inconsistent
  (for example if next_in or next_out was NULL), Z_MEM_ERROR if there was not
  enough memory, Z_BUF_ERROR if no progress is possible or if there was not
  enough room in the output buffer when Z_FINISH is used. In the Z_DATA_ERROR
  case, the application may then call inflateSync to look for a good
  compression block.}

function inflateEnd(var z: z_stream): int;
  {All dynamically allocated data structures for this stream are freed.
  This function discards any unprocessed input and does not flush any
  pending output.

    inflateEnd returns Z_OK if success, Z_STREAM_ERROR if the stream state
  was inconsistent. In the error case, msg may be set but then points to a
  static string (which must not be deallocated).}


(***************************************************************************)
(************************  Advanced functions  *****************************)
(***************************************************************************)


function deflateInit2(var strm: z_stream; level, method, windowBits, memLevel, strategy: int): int;
  {This is another version of deflateInit with more compression options. The
  fields next_in, zalloc, zfree and opaque must be initialized before by
  the caller.

    The method parameter is the compression method. It must be Z_DEFLATED in
  this version of the library. (Method 9 will allow a 64K history buffer and
  partial block flushes.)

    The windowBits parameter is the base two logarithm of the window size
  (the size of the history buffer).  It should be in the range 8..15 for this
  version of the library (the value 16 will be allowed for method 9). Larger
  values of this parameter result in better compression at the expense of
  memory usage. The default value is 15 if deflateInit is used instead.

    The memLevel parameter specifies how much memory should be allocated
  for the internal compression state. memLevel=1 uses minimum memory but
  is slow and reduces compression ratio; memLevel=9 uses maximum memory
  for optimal speed. The default value is 8. See zconf.h for total memory
  usage as a function of windowBits and memLevel.

    The strategy parameter is used to tune the compression algorithm. Use the
  value Z_DEFAULT_STRATEGY for normal data, Z_FILTERED for data produced by a
  filter (or predictor), or Z_HUFFMAN_ONLY to force Huffman encoding only (no
  string match).  Filtered data consists mostly of small values with a
  somewhat random distribution. In this case, the compression algorithm is
  tuned to compress them better. The effect of Z_FILTERED is to force more
  Huffman coding and less string matching; it is somewhat intermediate
  between Z_DEFAULT and Z_HUFFMAN_ONLY. The strategy parameter only affects
  the compression ratio but not the correctness of the compressed output even
  if it is not set appropriately.

    If next_in is not null, the library will use this buffer to hold also
  some history information; the buffer must either hold the entire input
  data, or have at least 1<<(windowBits+1) bytes and be writable. If next_in
  is null, the library will allocate its own history buffer (and leave next_in
  null). next_out need not be provided here but must be provided by the
  application for the next call of deflate().

    If the history buffer is provided by the application, next_in must
  must never be changed by the application since the compressor maintains
  information inside this buffer from call to call; the application
  must provide more input only by increasing avail_in. next_in is always
  reset by the library in this case.

     deflateInit2 returns Z_OK if success, Z_MEM_ERROR if there was
  not enough memory, Z_STREAM_ERROR if a parameter is invalid (such as
  an invalid method). msg is set to null if there is no error message.
  deflateInit2 does not perform any compression: this will be done by
  deflate().}

function deflateSetDictionary(var strm: z_stream; dictionary: pBytef; dictLength: uint): int;
  {Initializes the compression dictionary (history buffer) from the given
  byte sequence without producing any compressed output. This function must
  be called immediately after deflateInit or deflateInit2, before any call
  of deflate. The compressor and decompressor must use exactly the same
  dictionary (see inflateSetDictionary).
    The dictionary should consist of strings (byte sequences) that are likely
  to be encountered later in the data to be compressed, with the most commonly
  used strings preferably put towards the end of the dictionary. Using a
  dictionary is most useful when the data to be compressed is short and
  can be predicted with good accuracy; the data can then be compressed better
  than with the default empty dictionary. In this version of the library,
  only the last 32K bytes of the dictionary are used.
    Upon return of this function, strm->adler is set to the Adler32 value
  of the dictionary; the decompressor may later use this value to determine
  which dictionary has been used by the compressor. (The Adler32 value
  applies to the whole dictionary even if only a subset of the dictionary is
  actually used by the compressor.)

    deflateSetDictionary returns Z_OK if success, or Z_STREAM_ERROR if a
  parameter is invalid (such as NULL dictionary) or the stream state
  is inconsistent (for example if deflate has already been called for this
  stream). deflateSetDictionary does not perform any compression: this will
  be done by deflate().}

function deflateCopy(dest: z_streamp; source: z_streamp): int;
  {Sets the destination stream as a complete copy of the source stream.  If
  the source stream is using an application-supplied history buffer, a new
  buffer is allocated for the destination stream.  The compressed output
  buffer is always application-supplied. It's the responsibility of the
  application to provide the correct values of next_out and avail_out for the
  next call of deflate.

    This function can be useful when several compression strategies will be
  tried, for example when there are several ways of pre-processing the input
  data with a filter. The streams that will be discarded should then be freed
  by calling deflateEnd.  Note that deflateCopy duplicates the internal
  compression state which can be quite large, so this strategy is slow and
  can consume lots of memory.

    deflateCopy returns Z_OK if success, Z_MEM_ERROR if there was not
  enough memory, Z_STREAM_ERROR if the source stream state was inconsistent
  (such as zalloc being NULL). msg is left unchanged in both source and
  destination.}

function deflateReset(var strm: z_stream): int;
  {This function is equivalent to deflateEnd followed by deflateInit,
  but does not free and reallocate all the internal compression state.
  The stream will keep the same compression level and any other attributes
  that may have been set by deflateInit2.

      deflateReset returns Z_OK if success, or Z_STREAM_ERROR if the source
   stream state was inconsistent (such as zalloc or state being nil).}

function deflateParams(var strm: z_stream; level: int; strategy: int): int;
  {Dynamically update the compression level and compression strategy.
  This can be used to switch between compression and straight copy of
  the input data, or to switch to a different kind of input data requiring
  a different strategy. If the compression level is changed, the input
  available so far is compressed with the old level (and may be flushed);
  the new level will take effect only at the next call of deflate().

    Before the call of deflateParams, the stream state must be set as for
  a call of deflate(), since the currently available input may have to
  be compressed and flushed. In particular, strm->avail_out must be non-zero.

    deflateParams returns Z_OK if success, Z_STREAM_ERROR if the source
  stream state was inconsistent or if a parameter was invalid, Z_BUF_ERROR
  if strm->avail_out was zero.}


function inflateInit2(var z: z_stream; windowBits: int): int;
  {This is another version of inflateInit with an extra parameter. The
  fields next_in, avail_in, zalloc, zfree and opaque must be initialized
  before by the caller.

    The windowBits parameter is the base two logarithm of the maximum window
  size (the size of the history buffer).  It should be in the range 8..15 for
  this version of the library. The default value is 15 if inflateInit is used
  instead. If a compressed stream with a larger window size is given as
  input, inflate() will return with the error code Z_DATA_ERROR instead of
  trying to allocate a larger window.

     inflateInit2 returns Z_OK if success, Z_MEM_ERROR if there was not enough
  memory, Z_STREAM_ERROR if a parameter is invalid (such as a negative
  memLevel). msg is set to null if there is no error message.  inflateInit2
  does not perform any decompression apart from reading the zlib header if
  present: this will be done by inflate(). (So next_in and avail_in may be
  modified, but next_out and avail_out are unchanged.)}

function inflateInit_(z: z_streamp; const version: str255; stream_size: int): int;
function inflateInit2_(var z: z_stream; w: int; const version: str255; stream_size: int): int;
  {Another two version of inflateInit with an extra parameters}

function inflateReset(var z: z_stream): int;
  {This function is equivalent to inflateEnd followed by inflateInit,
  but does not free and reallocate all the internal decompression state.
  The stream will keep attributes that may have been set by inflateInit2.

  inflateReset returns Z_OK if success, or Z_STREAM_ERROR if the source
  stream state was inconsistent (such as zalloc or state being NULL).}

function inflateSetDictionary(var z: z_stream; dictionary: pBytef; dictLength: uInt): int;
  {Initializes the decompression dictionary from the given uncompressed byte
  sequence. This function must be called immediately after a call of inflate
  if this call returned Z_NEED_DICT. The dictionary chosen by the compressor
  can be determined from the Adler32 value returned by this call of
  inflate. The compressor and decompressor must use exactly the same
  dictionary (see deflateSetDictionary).

    inflateSetDictionary returns Z_OK if success, Z_STREAM_ERROR if a
  parameter is invalid (such as NULL dictionary) or the stream state is
  inconsistent, Z_DATA_ERROR if the given dictionary doesn't match the
  expected one (incorrect Adler32 value). inflateSetDictionary does not
  perform any decompression: this will be done by subsequent calls of
  inflate().}

function inflateSync(var z: z_stream): int;
  {Skips invalid compressed data until a full flush point (see above the
  description of deflate with Z_FULL_FLUSH) can be found, or until all
  available input is skipped. No output is provided.

    inflateSync returns Z_OK if a full flush point has been found, Z_BUF_ERROR
  if no more input was provided, Z_DATA_ERROR if no flush point has been found,
  or Z_STREAM_ERROR if the stream structure was inconsistent. In the success
  case, the application may save the current current value of total_in which
  indicates where valid compressed data was found. In the error case, the
  application may repeatedly call inflateSync, providing more input each time,
  until success or end of the input data.}


function inflateSyncPoint(var z: z_stream): int;
  {-returns true if inflate is currently at the end of a block generated
   by Z_SYNC_FLUSH or Z_FULL_FLUSH.}




(***************************************************************************)
(******************  Utility functions except GZ..  ************************)
(***************************************************************************)

function compress2(        dest: pBytef;
                    var destLen: uLong;
                   const source: array of byte;
                      sourceLen: uLong;
                          level: int): int;
  {-Compresses the source into the destination buffer with variable level}

  {level has the same meaning as in deflateInit.  sourceLen is the byte
   length of the source buffer. Upon entry, destLen is the total size of the
   destination buffer, which must be at least 0.1% larger than sourceLen plus
   12 bytes. Upon exit, destLen is the actual size of the compressed buffer.

   compress2 returns Z_OK if success, Z_MEM_ERROR if there was not enough
   memory, Z_BUF_ERROR if there was not enough room in the output buffer,
   Z_STREAM_ERROR if the level parameter is invalid.}


function compress(        dest: pBytef;
                   var destLen: uLong;
                  const source: array of byte;
                     sourceLen: uLong): int;
 {-Compresses source into destination buffer with level=Z_DEFAULT_COMPRESSION}


function uncompress (        dest: pBytef;
                      var destLen: uLong;
                     const source: array of byte;
                        sourceLen: uLong): int;

  {Decompresses the source buffer into the destination buffer.}
  {SourceLen is the byte length of the source buffer. Upon entry, destLen is
  the total size of the destination buffer, which must be large enough to
  hold the entire uncompressed data. (The size of the uncompressed data must
  have been saved previously by the compressor and transmitted to the
  decompressor by some mechanism outside the scope of this compression
  library.)
  Upon exit, destLen is the actual size of the compressed buffer.
  This function can be used to decompress a whole file at once if the
  input file is mmap'ed.

  uncompress returns Z_OK if success, Z_MEM_ERROR if there was not
  enough memory, Z_BUF_ERROR if there was not enough room in the output
  buffer, or Z_DATA_ERROR if the input data was corrupted.}


(***************************************************************************)
(**************************  Misc functions  *******************************)
(***************************************************************************)

function zlibVersion: str255;
  {-The application can compare zlibVersion and ZLIB_VERSION for consistency.
  If the first character differs, the library code actually used is
  not compatible with the zlib.h header file used by the application.
  This check is automatically made by deflateInit and inflateInit. }

function zError(err: int): str255;
  {-conversion of error code to string}


procedure zmemcpy(destp: pBytef; sourcep: pBytef; len: uInt);
function  zmemcmp(s1p, s2p: pBytef; len: uInt): int;
procedure zmemzero(destp: pBytef; len: uInt);
procedure zcfree(opaque: voidpf; ptr: voidpf);
function  zcalloc(opaque: voidpf; items: uInt; size: uInt): voidpf;

implementation

uses ZDeflate, ZInflate, ZUtil;

{Transfer to corresponding functions in ZUtil}
procedure zmemcpy(destp: pBytef; sourcep: pBytef; len: uInt);
begin
  ZUtil.zmemcpy(destp, sourcep, len);
end;

{---------------------------------------------------------------------------}
function  zmemcmp(s1p, s2p: pBytef; len: uInt): int;
begin
  zmemcmp := ZUtil.zmemcmp(s1p, s2p, len);
end;

{---------------------------------------------------------------------------}
procedure zmemzero(destp: pBytef; len: uInt);
begin
  ZUtil.zmemzero(destp, len);
end;

{---------------------------------------------------------------------------}
procedure zcfree(opaque: voidpf; ptr: voidpf);
begin
  ZUtil.zcfree(opaque, ptr);
end;

{---------------------------------------------------------------------------}
function zcalloc(opaque: voidpf; items: uInt; size: uInt): voidpf;
begin
  zcalloc := ZUtil.zcalloc(opaque, items, size);
end;


{Transfer to corresponding functions in ZDeflate/ZInflate}

{---------------------------------------------------------------------------}
function deflateInit(var strm: z_stream; level: int): int;
begin
  deflateInit := ZDeflate.deflateInit(strm,level);
end;


{---------------------------------------------------------------------------}
function deflate(var strm: z_stream; flush: int): int;
begin
  deflate := ZDeflate.deflate(strm, flush);
end;


{---------------------------------------------------------------------------}
function deflateEnd(var strm: z_stream): int;
begin
  deflateEnd := ZDeflate.deflateEnd(strm);
end;


{---------------------------------------------------------------------------}
function deflateInit2(var strm: z_stream; level, method, windowBits, memLevel, strategy: int): int;
begin
  deflateInit2 := ZDeflate.deflateInit2(strm, level, method, windowBits, memLevel, strategy);
end;


{---------------------------------------------------------------------------}
function deflateSetDictionary(var strm: z_stream; dictionary: pBytef; dictLength: uint): int;
begin
  deflateSetDictionary := ZDeflate.deflateSetDictionary(strm, dictionary, dictLength);
end;


{---------------------------------------------------------------------------}
function deflateCopy(dest: z_streamp; source: z_streamp): int;
begin
  deflateCopy := ZDeflate.deflateCopy(dest, source);
end;


{---------------------------------------------------------------------------}
function deflateReset(var strm: z_stream): int;
begin
  deflateReset := ZDeflate.deflateReset(strm);
end;


{---------------------------------------------------------------------------}
function deflateParams(var strm: z_stream; level: int; strategy: int): int;
begin
  deflateParams := ZDeflate.deflateParams(strm, level, strategy);
end;


{---------------------------------------------------------------------------}
function inflateInit(var z: z_stream): int;
begin
  inflateInit := ZInflate.inflateInit(z);
end;


{---------------------------------------------------------------------------}
function inflateInit_(z: z_streamp; const version: str255; stream_size: int): int;
begin
  inflateInit_ := ZInflate.inflateInit_(z, version, stream_size);
end;


{---------------------------------------------------------------------------}
function inflateInit2_(var z: z_stream; w: int; const version: str255; stream_size: int): int;
begin
  inflateInit2_ := ZInflate.inflateInit2_(z, w, version, stream_size);
end;


{---------------------------------------------------------------------------}
function inflateInit2(var z: z_stream; windowBits: int): int;
begin
  inflateInit2 := ZInflate.inflateInit2(z, windowBits);
end;


{---------------------------------------------------------------------------}
function inflateEnd(var z: z_stream): int;
begin
  inflateEnd := ZInflate.inflateEnd(z);
end;


{---------------------------------------------------------------------------}
function inflateReset(var z: z_stream): int;
begin
  inflateReset :=  ZInflate.inflateReset(z);
end;


{---------------------------------------------------------------------------}
function inflate(var z: z_stream; f: int): int;
begin
  inflate := ZInflate.inflate(z, f);
end;


{---------------------------------------------------------------------------}
function inflateSetDictionary(var z: z_stream; dictionary: pBytef; dictLength: uInt): int;
begin
  inflateSetDictionary := ZInflate.inflateSetDictionary(z, dictionary, dictLength);
end;


{---------------------------------------------------------------------------}
function inflateSync(var z: z_stream): int;
begin
  inflateSync := ZInflate.inflateSync(z);
end;


{---------------------------------------------------------------------------}
function inflateSyncPoint(var z: z_stream): int;
begin
  inflateSyncPoint := ZInflate.inflateSyncPoint(z);
end;


(***************************************************************************)
(***************************************************************************)

{---------------------------------------------------------------------------}
function zlibVersion: str255;
begin
  zlibVersion := ZLIB_VERSION;
end;

{---------------------------------------------------------------------------}
function zError(err: int): str255;
begin
  zError := z_errmsg[Z_NEED_DICT-err];
end;


{---------------------------------------------------------------------------}
{---------------------------------------------------------------------------}
{---------------------------------------------------------------------------}


{---------------------------------------------------------------------------}
function compress2(        dest: pBytef;
                    var destLen: uLong;
                   const source: array of byte;
                      sourceLen: uLong;
                          level: int): int;
 {-Compresses the source into the destination buffer with variable level}
var
  stream: z_stream;
  err: int;
begin
  stream.next_in := pBytef(@source);
  stream.avail_in := uInt(sourceLen);
  {$ifdef MAXSEG_64K}
    {Check for source > 64K on 16-bit machine:}
    if uLong(stream.avail_in) <> sourceLen then begin
      compress2 := Z_BUF_ERROR;
      exit;
    end;
  {$endif}
  stream.next_out := dest;
  stream.avail_out := uInt(destLen);
  if uLong(stream.avail_out) <> destLen then begin
    compress2 := Z_BUF_ERROR;
    exit;
  end;

  stream.zalloc := nil;       {alloc_func(0);}
  stream.zfree := nil;        {free_func(0);}
  stream.opaque := nil;       {voidpf(0);}

  err := ZDeflate.deflateInit(stream, level);
  if err<>Z_OK then begin
    compress2 := err;
    exit;
  end;

  err := ZDeflate.deflate(stream, Z_FINISH);
  if err<>Z_STREAM_END then begin
    ZDeflate.deflateEnd(stream);
    if err=Z_OK then compress2 := Z_BUF_ERROR else compress2 := err;
    exit;
  end;
  destLen := stream.total_out;

  err := ZDeflate.deflateEnd(stream);
  compress2 := err;
end;


{---------------------------------------------------------------------------}
function compress(dest: pBytef; var destLen: uLong; const source: array of byte; sourceLen: uLong): int;
  {-Compresses source into destination buffer with level=Z_DEFAULT_COMPRESSION}
begin
  compress := compress2(dest, destLen, source, sourceLen, Z_DEFAULT_COMPRESSION);
end;



{---------------------------------------------------------------------------}
function uncompress (        dest: pBytef;
                      var destLen: uLong;
                     const source: array of byte;
                        sourceLen: uLong): int;
  {-Decompresses the source buffer into the destination buffer.}
var
  stream: z_stream;
  err: int;
begin
  stream.next_in := pBytef(@source);
  stream.avail_in := uInt(sourceLen);
  { Check for source > 64K on 16-bit machine: }
  if uLong(stream.avail_in) <> sourceLen then begin
    uncompress := Z_BUF_ERROR;
    exit;
  end;

  stream.next_out := dest;
  stream.avail_out := uInt(destLen);
  if uLong(stream.avail_out) <> destLen then begin
    uncompress := Z_BUF_ERROR;
    exit;
  end;

  stream.zalloc := nil;       { alloc_func(0); }
  stream.zfree := nil;        { free_func(0); }

  err := ZInflate.inflateInit(stream);
  if err<>Z_OK then begin
    uncompress := err;
    exit;
  end;

  err := ZInflate.inflate(stream, Z_FINISH);
  if err<>Z_STREAM_END then begin
    ZInflate.inflateEnd(stream);
    if err=Z_OK then uncompress := Z_BUF_ERROR else uncompress := err;
    exit;
  end;
  destLen := stream.total_out;

  err := ZInflate.inflateEnd(stream);
  uncompress := err;
end;

end.
