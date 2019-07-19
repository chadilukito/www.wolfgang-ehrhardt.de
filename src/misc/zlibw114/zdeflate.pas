unit zDeflate;

(************************************************************************
  Orginal: deflate.h -- internal compression state
           deflate.c -- compress data using the deflation algorithm
  Copyright (C) 1995-2002 Jean-loup Gailly.

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:
  Aug 2000
    - ZLIB 113 changes
  Feb 2002
    - removed forward functions
    - declared compress_funcs far
    - removed function deflateInit_
    - Source code reformating/reordering
    - $ifdef ASMV removed
    - made code for $ifdef FASTEST usable
  Mar 2002
    - ZLIB 114 changes
  Jan 2003 @-Operator for FPC in configuration_table
  Mar 2005
    - {$ifdef UseFar}
    - Code cleanup for WWW upload
  May 2005
    - ulg typecast in deflate_stored to avoid D4+ warnings
    - Rangecheck off for assert in UNALIGNED_OK else branch
  Jul 2009
    - D12 fixes
  Sep 2015
    - FPC 3 / FPC_Procvar
  ------------------------------------------------------------------------


*************************************************************************)



{  ALGORITHM

       The "deflation" process depends on being able to identify portions
       of the input text which are identical to earlier input (within a
       sliding window trailing behind the input currently being processed).

       The most straightforward technique turns out to be the fastest for
       most input files: try all possible matches and select the longest.
       The key feature of this algorithm is that insertions into the string
       dictionary are very simple and thus fast, and deletions are avoided
       completely. Insertions are performed at each input character, whereas
       string matches are performed only when the previous match ends. So it
       is preferable to spend more time in matches to allow very fast string
       insertions and avoid deletions. The matching algorithm for small
       strings is inspired from that of Rabin & Karp. A brute force approach
       is used to find longer strings when a small match has been found.
       A similar algorithm is used in comic (by Jan-Mark Wams) and freeze
       (by Leonid Broukhis).
          A previous version of this file used a more sophisticated algorithm
       (by Fiala and Greene) which is guaranteed to run in linear amortized
       time, but has a larger average cost, uses more memory and is patented.
       However the F&G algorithm may be faster for some highly redundant
       files if the parameter max_chain_length (described below) is too large.

   ACKNOWLEDGEMENTS

       The idea of lazy evaluation of matches is due to Jan-Mark Wams, and
       I found it in 'freeze' written by Leonid Broukhis.
       Thanks to many people for bug reports and testing.

   REFERENCES

       Deutsch, L.P.,"'Deflate' Compressed Data Format Specification".
       Available in ftp.uu.net:/pub/archiving/zip/doc/deflate-1.1.doc

       A description of the Rabin and Karp algorithm is given in the book
          "Algorithms" by R. Sedgewick, Addison-Wesley, p252.

       Fiala,E.R., and Greene,D.H.
          Data Compression with Finite Windows, Comm.ACM, 32,4 (1989) 490-595}

{ $Id: deflate.c,v 1.14 1996/07/02 12:40:55 me Exp $}

interface

{$x+}



uses
   zlibh;


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




                        {Advanced functions}

{The following functions are needed only in some special applications.}


function deflateInit2 (  var strm: z_stream;
                            level: int;
                           method: int;
                       windowBits: int;
                         memLevel: int;
                         strategy: int): int;

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
     Upon return of this function, strm.adler is set to the Adler32 value
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
   be compressed and flushed. In particular, strm.avail_out must be non-zero.

     deflateParams returns Z_OK if success, Z_STREAM_ERROR if the source
   stream state was inconsistent or if a parameter was invalid, Z_BUF_ERROR
   if strm.avail_out was zero.}


var
   deflate_copyright: string[60];

  {If you use the zlib library in a product, an acknowledgment is welcome
   in the documentation of your product. If for some reason you cannot
   include such an acknowledgment, I would appreciate that you keep this
   copyright string in the executable of your product.}


implementation

{$I zconf.inc}

uses
  zutil, trees, adler;


{$ifdef VER70}
  {$define UseFar}
{$endif}

{$ifdef VER80}
  {$define UseFar}
{$endif}

type
   block_state = (
    need_more,      {block not completed, need more input or more output}
    block_done,     {block flush performed}
    finish_started, {finish started, need only more output at next deflate}
    finish_done);   {finish done, accept no more input or output}

{Compression function. Returns the block state after the call.}
type
  compress_func = function(var s: deflate_state; flush: int): block_state;

const
  ZNIL = 0;  {Tail of hash chains}

const
  TOO_FAR = 4096; {Matches of length 3 are discarded if their distance exceeds TOO_FAR}

const
  MIN_LOOKAHEAD = (MAX_MATCH+MIN_MATCH+1); {Minimum amount of lookahead, except at the end of the input file.
                                           See deflate.c for comments about the MIN_MATCH+1.}



{---------------------------------------------------------------------------}
function read_buf(strm: z_streamp; buf: pBytef; size: unsigned): int;
  {-Read a new buffer from the current input stream, update the adler32
    and total number of bytes read.  All deflate() input goes through
    this function so some applications may wish to modify it to avoid
    allocating a large strm^.next_in buffer and copying from it.
    (See also flush_pending()).}
var
  len: unsigned;
begin
  len := strm^.avail_in;
  if len>size then len := size;
  if len=0 then begin
    read_buf := 0;
    exit;
  end;
  dec(strm^.avail_in, len);
  if deflate_state_ptr(strm^.state)^.noheader = 0 then begin
    strm^.adler := adler32(strm^.adler, strm^.next_in, len);
  end;
  zmemcpy(buf, strm^.next_in, len);
  inc(strm^.next_in, len);
  inc(strm^.total_in, len);
  read_buf := int(len);
end;




{---------------------------------------------------------------------------}
procedure fill_window(var s: deflate_state);
  {-Fill the window when the lookahead becomes insufficient.
    Updates strstart and lookahead.

  IN assertion: lookahead < MIN_LOOKAHEAD
  OUT assertions: strstart <= window_size-MIN_LOOKAHEAD
     At least one byte has been read, or avail_in = 0; reads are
     performed for at least two bytes (required for the zip translate_eol
     option -- not supported here).}
var
  n, m: unsigned;
  p: pPosf;
  more: unsigned;    {Amount of free space at the end of the window.}
  wsize: uInt;
begin
   wsize := s.w_size;
   repeat
     more := unsigned(s.window_size -ulg(s.lookahead) -ulg(s.strstart));

     {Deal with !@#$% 64K limit:}
     if (more=0) and (s.strstart=0) and (s.lookahead=0) then more := wsize
     else if (more = unsigned(-1)) then begin
       {Very unlikely, but possible on 16 bit machine if strstart = 0
        and lookahead = 1 (input done one byte at time)}
       dec(more);

       {If the window is almost full and there is insufficient lookahead,
        move the upper half to the lower one to make room in the upper half.}
     end
     else if (s.strstart >= wsize+(wsize-MIN_LOOKAHEAD)) then begin
       zmemcpy(pBytef(s.window), pBytef(@(s.window^[wsize])), unsigned(wsize));
       dec(s.match_start, wsize);
       dec(s.strstart, wsize); {we now have strstart >= MAX_DIST}
       dec(s.block_start, long(wsize));

       {Slide the hash table (could be avoided with 32 bit values
        at the expense of memory usage). We slide even when level = 0
        to keep the hash table consistent if we switch back to level > 0
        later. (Using level 0 permanently is not an optimal usage of
        zlib, so we don't care about this pathological case.)}

       n := s.hash_size;
       p := @s.head^[n];
       repeat
         dec(p);
         m := p^;
         if m>=wsize then p^ := pos(m-wsize) else p^ := pos(ZNIL);
         dec(n);
       until (n=0);

       n := wsize;
       {$ifndef FASTEST}
          p := @s.prev^[n];
          repeat
            dec(p);
            m := p^;
            if m>=wsize then p^ := pos(m-wsize) else p^:= pos(ZNIL);
            {If n is not on any hash chain, prev^[n] is garbage but
             its value will never be used.}
            dec(n);
          until (n=0);
       {$endif}
       inc(more, wsize);
     end;

     if s.strm^.avail_in=0 then exit;

     {* If there was no sliding:
      *    strstart <= WSIZE+MAX_DIST-1 && lookahead <= MIN_LOOKAHEAD - 1 &&
      *    more == window_size - lookahead - strstart
      * => more >= window_size - (MIN_LOOKAHEAD-1 + WSIZE + MAX_DIST-1)
      * => more >= window_size - 2*WSIZE + 2
      * In the BIG_MEM or MMAP case (not yet supported),
      *   window_size == input_size + MIN_LOOKAHEAD  &&
      *   strstart + s->lookahead <= input_size => more >= MIN_LOOKAHEAD.
      * Otherwise, window_size == 2*WSIZE so more >= 2.
      * If there was sliding, more >= WSIZE. So in all cases, more >= 2.}

     {$ifdef DEBUG}
       Assert(more >= 2, 'more < 2');
     {$endif}

     n := read_buf(s.strm, pBytef(@(s.window^[s.strstart + s.lookahead])), more);
     inc(s.lookahead, n);

     {Initialize the hash value now that we have some input:}
     if s.lookahead >= MIN_MATCH then begin
       s.ins_h := s.window^[s.strstart];
       {UPDATE_HASH(s, s.ins_h, s.window[s.strstart+1]);}
       s.ins_h := ((s.ins_h shl s.hash_shift) xor s.window^[s.strstart+1])
                     and s.hash_mask;
       {$ifdef MIN_MATCH <> 3}
         Call UPDATE_HASH() MIN_MATCH-3 more times
       {$endif}
     end;

     {If the whole input has less than MIN_MATCH bytes, ins_h is garbage,
      but this is not important since only literal bytes will be emitted.}

   until (s.lookahead >= MIN_LOOKAHEAD) or (s.strm^.avail_in = 0);
end;





{---------------------------------------------------------------------------}
procedure flush_pending(var strm: z_stream);
  {-Flush as much pending output as possible. All deflate() output goes
    through this function so some applications may wish to modify it
    to avoid allocating a large strm^.next_out buffer and copying into it.
    (See also read_buf()).}
var
  len: unsigned;
  s: deflate_state_ptr;
begin
  s := deflate_state_ptr(strm.state);
  len := s^.pending;
  if len>strm.avail_out then len := strm.avail_out;
  if len=0 then exit;
  zmemcpy(strm.next_out, s^.pending_out, len);
  inc(strm.next_out, len);
  inc(s^.pending_out, len);
  inc(strm.total_out, len);
  dec(strm.avail_out, len);
  dec(s^.pending, len);
  if s^.pending=0 then s^.pending_out := pBytef(s^.pending_buf);
end;



{---------------------------------------------------------------------------}
procedure FLUSH_BLOCK_ONLY(var s: deflate_state; eof: boolean); {macro}
  {-Flush the current block, with given end-of-file flag.}
  {IN assertion: strstart is set to the end of the current match.}
begin
  if s.block_start >= 0 then begin
    _tr_flush_block(s, pcharf(@s.window^[unsigned(s.block_start)]), ulg(long(s.strstart) - s.block_start), eof);
  end
  else begin
    _tr_flush_block(s, pcharf(Z_NULL), ulg(long(s.strstart) - s.block_start), eof);
  end;
  s.block_start := s.strstart;
  flush_pending(s.strm^);
  {$ifdef DEBUG}
    Tracev('[FLUSH]');
  {$endif}
end;




{---------------------------------------------------------------------------}
procedure INSERT_STRING(var s: deflate_state; str: uInt; var match_head: IPos);
  {-Insert string str in the dictionary and set match_head to the previous head
    of the hash chain (the most recent string with same hash key). Return
    the previous length of the hash chain.
    If this file is compiled with -DFASTEST, the compression level is forced
    to 1, and no hash chains are maintained.
    IN  assertion: all calls to to INSERT_STRING are made with consecutive
       input characters and the first MIN_MATCH bytes of str are valid
       (except for the last MIN_MATCH-1 bytes of the input file).}
begin
  s.ins_h := ((s.ins_h shl s.hash_shift) xor (s.window^[(str) + (MIN_MATCH-1)])) and s.hash_mask;
  match_head := s.head^[s.ins_h];
  {$ifndef FASTEST}
    s.prev^[(str) and s.w_mask] := match_head;
  {$endif}
  s.head^[s.ins_h] := pos(str);
end;


{$undef DO_UNALIGNED_OK}
{$ifdef UNALIGNED_OK}
{$ifdef MAX_MATCH_IS_258}
  {$define DO_UNALIGNED_OK}
{$endif}
{$endif}




{$ifndef FASTEST}

{---------------------------------------------------------------------------}
function longest_match(var s: deflate_state; cur_match: IPos): uInt;
  {-Set match_start to the longest match starting at the given string and
    return its length. Matches shorter or equal to prev_length are discarded,
    in which case the result is equal to prev_length and match_start is
    garbage.
    IN assertions: cur_match is the head of the hash chain for the current
      string (strstart) and its distance is <= MAX_DIST, and prev_length >= 1
    OUT assertion: the match length is not greater than s^.lookahead.}
label
  nextstep;
var
  chain_length: unsigned;  {max hash chain length}
  scan: pBytef;            {current string}
  match: pBytef;           {matched string}
  len: int;                {length of current match}
  best_len: int;           {best match length so far}
  nice_match: int;         {stop if match long enough}
  limit: IPos;

  prev: pzPosfArray;
  wmask: uInt;
  {$ifdef UNALIGNED_OK}
    strend: pBytef;
    scan_start: ush;
    scan_end: ush;
  {$else}
    strend: pBytef;
    scan_end1: byte;
    scan_end: byte;
  {$endif}
var
  MAX_DIST: uInt;

begin
  chain_length := s.max_chain_length;     {max hash chain length}
  scan := @(s.window^[s.strstart]);
  best_len := s.prev_length;              {best match length so far}
  nice_match := s.nice_match;             {stop if match long enough}


  MAX_DIST := s.w_size - MIN_LOOKAHEAD;
  {In order to simplify the code, particularly on 16 bit machines, match
  distances are limited to MAX_DIST instead of WSIZE.}

  if s.strstart > IPos(MAX_DIST) then limit := s.strstart - IPos(MAX_DIST)
  else limit := ZNIL;

  {Stop when cur_match becomes <= limit. To simplify the code,
  we prevent matches with the string of window index 0.}

  prev := s.prev;
  wmask := s.w_mask;

  {$ifdef UNALIGNED_OK}
    {Compare two bytes at a time. Note: this is not always beneficial.
     Try with and without -DUNALIGNED_OK to check.}

    strend := pBytef(@(s.window^[s.strstart + MAX_MATCH - 1]));
    scan_start := pushf(scan)^;
    {$ifopt R+} {$R-} {$define NoRangeCheck} {$endif}                 {*we}
    scan_end   := pushfArray(scan)^[best_len-1];   {fix}
    {$ifdef NoRangeCheck} {$R+} {$undef NoRangeCheck} {$endif}        {*we}
  {$else}
    strend := pBytef(@(s.window^[s.strstart + MAX_MATCH]));
    {$ifopt R+} {$R-} {$define NoRangeCheck} {$endif}
    scan_end1  := pzByteArray(scan)^[best_len-1];
    {$ifdef NoRangeCheck} {$R+} {$undef NoRangeCheck} {$endif}
    scan_end   := pzByteArray(scan)^[best_len];
  {$endif}

  {The code is optimized for HASH_BITS >= 8 and MAX_MATCH-2 multiple of 16.
   It is easy to get rid of this optimization if necessary.}
  {$ifdef DEBUG}
    Assert((s.hash_bits >= 8) and (MAX_MATCH = 258), 'Code too clever');
  {$endif}
  {Do not waste too much time if we already have a good match:}

  if s.prev_length>=s.good_match then chain_length := chain_length shr 2;

  {Do not look for matches beyond the end of the input. This is necessary
  to make deflate deterministic.}

  if uInt(nice_match) > s.lookahead then nice_match := s.lookahead;

  {$ifdef DEBUG}
    Assert(ulg(s.strstart) <= s.window_size-MIN_LOOKAHEAD, 'need lookahead');
  {$endif}

  repeat
    {$ifdef DEBUG}
      Assert(cur_match < s.strstart, 'no future');
    {$endif}
    match := @(s.window^[cur_match]);

    {Skip to next match if the match length cannot increase
    or if the match length is less than 2:}

    {$ifdef DO_UNALIGNED_OK}
      {This code assumes sizeof(unsigned short) = 2. Do not use
      UNALIGNED_OK if your compiler uses a different size.}

      {$ifopt R+} {$R-} {$define NoRangeCheck} {$endif}
      if (pushfArray(match)^[best_len-1] <> scan_end) or (pushf(match)^ <> scan_start) then goto nextstep;
      {$ifdef NoRangeCheck} {$R+} {$undef NoRangeCheck} {$endif}

      {It is not necessary to compare scan[2] and match[2] since they are
      always equal when the other bytes match, given that the hash keys
      are equal and that HASH_BITS >= 8. Compare 2 bytes at a time at
      strstart+3, +5, ... up to strstart+257. We check for insufficient
      lookahead only every 4th comparison; the 128th check will be made
      at strstart+257. If MAX_MATCH-2 is not a multiple of 8, it is
      necessary to put more guard bytes at the end of the window, or
      to check more often for insufficient lookahead.}

      {$ifdef DEBUG}
        Assert(pzByteArray(scan)^[2] = pzByteArray(match)^[2], 'scan[2]?');
      {$endif}
      inc(scan);
      inc(match);

      repeat
        inc(scan,2); inc(match,2); if (pushf(scan)^<>pushf(match)^) then break;
        inc(scan,2); inc(match,2); if (pushf(scan)^<>pushf(match)^) then break;
        inc(scan,2); inc(match,2); if (pushf(scan)^<>pushf(match)^) then break;
        inc(scan,2); inc(match,2); if (pushf(scan)^<>pushf(match)^) then break;
      until (ptr2int(scan) >= ptr2int(strend));
      {The funny "do while" generates better code on most compilers}

      {Here, scan <= window+strstart+257}
      {$ifdef DEBUG}
        {$ifopt R+} {$define RangeCheck} {$endif} {$R-}
        Assert(ptr2int(scan) <= ptr2int(@(s.window^[unsigned(s.window_size-1)])), 'wild scan');
        {$ifdef RangeCheck} {$R+} {$undef RangeCheck} {$endif}
      {$endif}
      if (scan^ = match^) then
        inc(scan);

      len := (MAX_MATCH - 1) - int(ptr2int(strend)) + int(ptr2int(scan));
      scan := strend;
      dec(scan, (MAX_MATCH-1));

    {$else} {UNALIGNED_OK}

      {$ifopt R+} {$R-} {$define NoRangeCheck} {$endif}
        if (pzByteArray(match)^[best_len] <> scan_end) or
           (pzByteArray(match)^[best_len-1] <> scan_end1) or
           (match^ <> scan^) then goto nextstep; {continue;}
      {$ifdef NoRangeCheck} {$R+} {$undef NoRangeCheck} {$endif}
      inc(match);
      if match^<>pzByteArray(scan)^[1] then goto nextstep; {continue;}

      {The check at best_len-1 can be removed because it will be made
      again later. (This heuristic is not always a win.)
      It is not necessary to compare scan[2] and match[2] since they
      are always equal when the other bytes match, given that
      the hash keys are equal and that HASH_BITS >= 8.}

      inc(scan, 2);
      inc(match);
      {$ifdef DEBUG}
        Assert(scan^ = match^, 'match[2]?');
      {$endif}
      {We check for insufficient lookahead only every 8th comparison;
        the 256th check will be made at strstart+258.}

      repeat
        inc(scan); inc(match); if (scan^ <> match^) then break;
        inc(scan); inc(match); if (scan^ <> match^) then break;
        inc(scan); inc(match); if (scan^ <> match^) then break;
        inc(scan); inc(match); if (scan^ <> match^) then break;
        inc(scan); inc(match); if (scan^ <> match^) then break;
        inc(scan); inc(match); if (scan^ <> match^) then break;
        inc(scan); inc(match); if (scan^ <> match^) then break;
        inc(scan); inc(match); if (scan^ <> match^) then break;
      until (ptr2int(scan) >= ptr2int(strend));

      {$ifdef DEBUG}
        {*we 05.2005, range check off}
        {$ifopt R+} {$define RangeCheck} {$endif} {$R-}
        Assert(ptr2int(scan)<=ptr2int(@(s.window^[unsigned(s.window_size-1)])), 'wild scan');
        {$ifdef RangeCheck} {$R+} {$undef RangeCheck} {$endif}
      {$endif}

      len := MAX_MATCH - int(ptr2int(strend) - ptr2int(scan));
      scan := strend;
      dec(scan, MAX_MATCH);

    {$endif} {UNALIGNED_OK}

    if len > best_len then begin
      s.match_start := cur_match;
      best_len := len;
      if len >= nice_match then break;
      {$ifopt R+} {$R-} {$define NoRangeCheck} {$endif}
      {$ifdef UNALIGNED_OK}
         scan_end := pzByteArray(scan)^[best_len-1];
      {$else}
         scan_end1:= pzByteArray(scan)^[best_len-1];
         scan_end := pzByteArray(scan)^[best_len];
      {$endif}
      {$ifdef NoRangeCheck} {$R+} {$undef NoRangeCheck} {$endif}
    end;

nextstep:

    cur_match := prev^[cur_match and wmask];
    dec(chain_length);
  until (cur_match <= limit) or (chain_length = 0);

  if uInt(best_len) <= s.lookahead then longest_match := uInt(best_len)
  else longest_match := s.lookahead;
end;


{$else} {FASTEST}

{---------------------------------------------------------------------------}
function longest_match(var s: deflate_state; cur_match: IPos): uInt;
  {-Set match_start to the longest match starting at the given string and
    return its length. Matches shorter or equal to prev_length are discarded,
    in which case the result is equal to prev_length and match_start is
    garbage.
    IN assertions: cur_match is the head of the hash chain for the current
      string (strstart) and its distance is <= MAX_DIST, and prev_length >= 1
    OUT assertion: the match length is not greater than s^.lookahead.}

  { Optimized version for level = 1 only}
var
  scan: pBytef;   {current string}
  match: pBytef;  {matched string}
  len: int;       {length of current match}
  strend: pBytef;
begin
  scan := @s.window^[s.strstart];
  strend := @s.window^[s.strstart + MAX_MATCH];


  {The code is optimized for HASH_BITS >= 8 and MAX_MATCH-2 multiple of 16.
  It is easy to get rid of this optimization if necessary.}
  {$ifdef DEBUG}
    Assert((s.hash_bits >= 8) and (MAX_MATCH = 258), 'Code too clever');
    Assert(ulg(s.strstart) <= s.window_size-MIN_LOOKAHEAD, 'need lookahead');
    Assert(cur_match < s.strstart, 'no future');
  {$endif}

  match := @(s.window^[cur_match]);

  {Return failure if the match length is less than 2:}
  if (match^<>scan^) or (pushfArray(match)^[1] <> pushfArray(scan)^[1]) then begin
    longest_match := MIN_MATCH-1;
    exit;
  end;

  {The check at best_len-1 can be removed because it will be made
  again later. (This heuristic is not always a win.)
  It is not necessary to compare scan[2] and match[2] since they
  are always equal when the other bytes match, given that
  the hash keys are equal and that HASH_BITS >= 8.}

  inc(scan,2);
  inc(match,2);

  {$ifdef DEBUG}
    Assert(scan^ = match^, 'match[2]?');
  {$endif}

  {We check for insufficient lookahead only every 8th comparison;
  the 256th check will be made at strstart+258.}

  repeat
    inc(scan); inc(match); if scan^<>match^ then break;
    inc(scan); inc(match); if scan^<>match^ then break;
    inc(scan); inc(match); if scan^<>match^ then break;
    inc(scan); inc(match); if scan^<>match^ then break;
    inc(scan); inc(match); if scan^<>match^ then break;
    inc(scan); inc(match); if scan^<>match^ then break;
    inc(scan); inc(match); if scan^<>match^ then break;
    inc(scan); inc(match); if scan^<>match^ then break;
  until (ptr2int(scan) >= ptr2int(strend));

  {$ifdef DEBUG}
    Assert(scan <= s.window+unsigned(s.window_size-1), 'wild scan');
  {$endif}

  len := MAX_MATCH - (ptr2int(strend) - ptr2int(scan));

  if len<MIN_MATCH then begin
    longest_match := MIN_MATCH - 1;
    exit;
  end;

  s.match_start := cur_match;
  if len <= s.lookahead then longest_match := len
  else longest_match := s.lookahead;
end;
{$endif} {FASTEST}



{$ifdef DEBUG}
const
  EQUAL = 0; {result of memcmp for equal strings}

{---------------------------------------------------------------------------}
procedure check_match(var s: deflate_state; start, match: IPos; length: int);
  {-Check that the match at match_start is indeed a match.}
begin
  exit;
  {check that the match is indeed a match}
  if zmemcmp(pBytef(@s.window^[match]), pBytef(@s.window^[start]), length)<>EQUAL then begin
    writeln(' start ',start,', match ',match ,' length ', length);
    repeat
      write(char8(s.window^[match]), char8(s.window^[start]));
      inc(match);
      inc(start);
      dec(length);
    until (length = 0);
    z_error('invalid match');
  end;
  if z_verbose>1 then begin
    write('\\[',start-match,',',length,']');
    repeat
       write(char8(s.window^[start]));
       inc(start);
       dec(length);
    until (length = 0);
  end;
end;
{$endif}




{---------------------------------------------------------------------------}
function deflate_stored(var s: deflate_state; flush: int): block_state; {$ifdef UseFar} far; {$endif}
  {-Copy without compression as much as possible from the input stream, return
    the current block state.
    This function does not insert new strings in the dictionary since
    uncompressible data is probably not useful. This function is used
    only for the level=0 compression option.
    NOTE: this function should be optimized to avoid extra copying from
    window to pending_buf.}
  {Stored blocks are limited to 0xffff bytes, pending_buf is limited
  to pending_buf_size, and each stored block has a 5 byte header:}
var
  max_block_size: ulg;
  max_start: ulg;
begin
  max_block_size := $ffff;
  if max_block_size>s.pending_buf_size - 5 then max_block_size := s.pending_buf_size - 5;

  {Copy as much as possible from input to output:}
  while true do begin
    {Fill the window as much as possible:}
    if s.lookahead <= 1 then begin
      {$ifdef DEBUG}
        Assert((s.strstart < s.w_size + {MAX_DIST}s.w_size-MIN_LOOKAHEAD) or
               (s.block_start >= long(s.w_size)), 'slide too late');
      {$endif}
      fill_window(s);
      if (s.lookahead=0) and (flush=Z_NO_FLUSH) then begin
        deflate_stored := need_more;
        exit;
      end;

      if s.lookahead=0 then break; {flush the current block}
    end;
    {$ifdef DEBUG}
      Assert(s.block_start >= long(0), 'block gone');
    {$endif}
    inc(s.strstart, s.lookahead);
    s.lookahead := 0;

    {Emit a stored block if pending_buf will be full:}
    max_start := s.block_start + max_block_size;
    if (s.strstart = 0) or (ulg(s.strstart) >= max_start) then begin
      {strstart = 0 is possible when wraparound on 16-bit machine}
      s.lookahead := uInt(ulg(s.strstart) - ulg(max_start));  {*we May2005: ulg typecast}
      s.strstart := uInt(max_start);
      {FLUSH_BLOCK(s, false);}
      FLUSH_BLOCK_ONLY(s, false);
      if s.strm^.avail_out=0 then begin
        deflate_stored := need_more;
        exit;
      end;
    end;

    {Flush if we may have to slide, otherwise block_start may become
    negative and the data will be gone:}

    if s.strstart - uInt(s.block_start) >= s.w_size-MIN_LOOKAHEAD then begin
      {FLUSH_BLOCK(s, false);}
      FLUSH_BLOCK_ONLY(s, false);
      if s.strm^.avail_out=0 then begin
        deflate_stored := need_more;
        exit;
      end;
    end;
  end;

  {FLUSH_BLOCK(s, flush = Z_FINISH);}
  FLUSH_BLOCK_ONLY(s, flush = Z_FINISH);
  if s.strm^.avail_out=0 then begin
    if flush = Z_FINISH then  deflate_stored := finish_started
    else deflate_stored := need_more;
    exit;
  end;

  if flush = Z_FINISH then deflate_stored := finish_done
  else deflate_stored := block_done;
end;



{---------------------------------------------------------------------------}
function deflate_fast(var s: deflate_state; flush: int): block_state; {$ifdef UseFar} far; {$endif}
  {-Compress as much as possible from the input stream, return the current block state.
    This function does not perform lazy evaluation of matches and inserts
    new strings in the dictionary only for unmatched strings or for short
    matches. It is used only for the fast compression options.}
var
  hash_head: IPos;     {head of the hash chain}
  bflush: boolean;     {set if current block must be flushed}
begin
  hash_head := ZNIL;
  while true do begin
    {Make sure that we always have enough lookahead, except
    at the end of the input file. We need MAX_MATCH bytes
    for the next match, plus MIN_MATCH bytes to insert the
    string following the next match.}

    if s.lookahead<MIN_LOOKAHEAD then begin
      fill_window(s);
      if (s.lookahead < MIN_LOOKAHEAD) and (flush = Z_NO_FLUSH) then begin
        deflate_fast := need_more;
        exit;
      end;
      if s.lookahead=0 then break; {flush the current block}
    end;

    {Insert the string window[strstart .. strstart+2] in the
    dictionary, and set hash_head to the head of the hash chain:}

    if s.lookahead>=MIN_MATCH then INSERT_STRING(s, s.strstart, hash_head);

    {Find the longest match, discarding those <= prev_length.
    At this point we have always match_length < MIN_MATCH}

    if (hash_head <> ZNIL) and (s.strstart-hash_head <= s.w_size-MIN_LOOKAHEAD) then begin
      {To simplify the code, we prevent matches with the string
      of window index 0 (in particular we have to avoid a match
      of the string with itself at the start of the input file).}
      if s.strategy<>Z_HUFFMAN_ONLY then s.match_length := longest_match (s, hash_head);
    end;
    if s.match_length >= MIN_MATCH then begin
      {$ifdef DEBUG}
        check_match(s, s.strstart, s.match_start, s.match_length);
      {$endif}
      bflush := _tr_tally(s, s.strstart-s.match_start, s.match_length-MIN_MATCH);
      dec(s.lookahead, s.match_length);

      {Insert new strings in the hash table only if the match length
      is not too large. This saves time but degrades compression.}

      {$ifndef FASTEST}
        if (s.match_length <= s.max_insert_length) and (s.lookahead >= MIN_MATCH) then begin
          dec(s.match_length); {string at strstart already in hash table}
          repeat
            inc(s.strstart);
            INSERT_STRING(s, s.strstart, hash_head);
            { strstart never exceeds WSIZE-MAX_MATCH, so there are
              always MIN_MATCH bytes ahead.}
            dec(s.match_length);
          until (s.match_length = 0);
          inc(s.strstart);
        end
        else
      {$endif}
      begin
        inc(s.strstart, s.match_length);
        s.match_length := 0;
        s.ins_h := s.window^[s.strstart];
        {UPDATE_HASH(s, s.ins_h, s.window[s.strstart+1]);}
        s.ins_h := ((s.ins_h shl s.hash_shift) xor s.window^[s.strstart+1]) and s.hash_mask;

        (*****
        {*we: Original c code does not compile if MIN_MATCH<>3!!!}
        if MIN_MATCH <> 3 then   {the linker removes this}
        begin
                  {Call UPDATE_HASH() MIN_MATCH-3 more times}
        end;
        *****)

        {If lookahead < MIN_MATCH, ins_h is garbage, but it does not
        matter since it will be recomputed at next deflate call.}

      end;
    end
    else begin
      {No match, output a literal byte}
      {$ifdef DEBUG}
        Tracevv(char8(s.window^[s.strstart]));
      {$endif}
      bflush := _tr_tally (s, 0, s.window^[s.strstart]);
      dec(s.lookahead);
      inc(s.strstart);
    end;
    if bflush then begin
      FLUSH_BLOCK_ONLY(s, false);
      if s.strm^.avail_out = 0 then begin
        deflate_fast := need_more;
        exit;
      end;
    end;
  end; {while true}

  FLUSH_BLOCK_ONLY(s, flush = Z_FINISH);
  if s.strm^.avail_out=0 then begin
    if flush = Z_FINISH then deflate_fast := finish_started
    else deflate_fast := need_more;
    exit;
  end;

  if flush=Z_FINISH then deflate_fast := finish_done
  else deflate_fast := block_done;

end;




{---------------------------------------------------------------------------}
function deflate_slow(var s: deflate_state; flush: int): block_state; {$ifdef UseFar} far; {$endif}
  {-Same as above, but achieves better compression. We use a lazy
    evaluation for matches: a match is finally adopted only if there is
    no better match at the next window position.}
var
  hash_head: IPos;       {head of hash chain}
  bflush: boolean;       {set if current block must be flushed}
var
  max_insert: uInt;
begin
  hash_head := ZNIL;

  {Process the input block.}
  while true do begin
    {Make sure that we always have enough lookahead, except
    at the end of the input file. We need MAX_MATCH bytes
    for the next match, plus MIN_MATCH bytes to insert the
    string following the next match.}

    if s.lookahead < MIN_LOOKAHEAD then begin
      fill_window(s);
      if (s.lookahead < MIN_LOOKAHEAD) and (flush = Z_NO_FLUSH) then begin
        deflate_slow := need_more;
        exit;
      end;
      if s.lookahead=0 then break; {flush the current block}
    end;

    {Insert the string window[strstart .. strstart+2] in the
    dictionary, and set hash_head to the head of the hash chain:}

    if s.lookahead>=MIN_MATCH then INSERT_STRING(s, s.strstart, hash_head);

    {Find the longest match, discarding those <= prev_length.}
    s.prev_length := s.match_length;
    s.prev_match := s.match_start;
    s.match_length := MIN_MATCH-1;

    if (hash_head <> ZNIL) and (s.prev_length < s.max_lazy_match) and
       (s.strstart - hash_head <= {MAX_DIST}(s.w_size-MIN_LOOKAHEAD)) then
    begin
      {To simplify the code, we prevent matches with the string
      of window index 0 (in particular we have to avoid a match
      of the string with itself at the start of the input file).}

      if s.strategy<>Z_HUFFMAN_ONLY then s.match_length := longest_match (s, hash_head);

      {longest_match() sets match_start}
      if (s.match_length <= 5) and ((s.strategy = Z_FILTERED) or
         ((s.match_length = MIN_MATCH) and
         (s.strstart - s.match_start > TOO_FAR))) then
      begin
        {If prev_match is also MIN_MATCH, match_start is garbage
        but we will ignore the current match anyway.}
        s.match_length := MIN_MATCH-1;
      end;
    end;

    {If there was a match at the previous step and the current
    match is not better, output the previous match:}
    if (s.prev_length >= MIN_MATCH) and (s.match_length <= s.prev_length) then begin
      max_insert := s.strstart + s.lookahead - MIN_MATCH;
      {Do not insert strings in hash table beyond this.}
      {$ifdef DEBUG}
        check_match(s, s.strstart-1, s.prev_match, s.prev_length);
      {$endif}
      bflush := _tr_tally(s, s.strstart-1-s.prev_match, s.prev_length - MIN_MATCH);

      {Insert in hash table all strings up to the end of the match.
      strstart-1 and strstart are already inserted. If there is not
      enough lookahead, the last two strings are not inserted in
      the hash table.}

      dec(s.lookahead, s.prev_length-1);
      dec(s.prev_length, 2);
      repeat
        inc(s.strstart);
        if s.strstart<=max_insert then INSERT_STRING(s, s.strstart, hash_head);
        dec(s.prev_length);
      until (s.prev_length = 0);
      s.match_available := false;
      s.match_length := MIN_MATCH-1;
      inc(s.strstart);

      if bflush then begin
        FLUSH_BLOCK_ONLY(s, false);
        if s.strm^.avail_out=0 then begin
          deflate_slow := need_more;
          exit;
        end;
      end;
    end
    else if s.match_available then begin
      {If there was no match at the previous position, output a
      single literal. If there was a match but the current match
      is longer, truncate the previous match to a single literal.}
      {$ifdef DEBUG}
        Tracevv(char8(s.window^[s.strstart-1]));
      {$endif}
      bflush := _tr_tally (s, 0, s.window^[s.strstart-1]);
      if bflush then FLUSH_BLOCK_ONLY(s, false);

      inc(s.strstart);
      dec(s.lookahead);
      if s.strm^.avail_out=0 then begin
        deflate_slow := need_more;
        exit;
      end;
    end
    else begin
      {There is no previous match to compare with, wait for
      the next step to decide.}
      s.match_available := true;
      inc(s.strstart);
      dec(s.lookahead);
    end;
  end;

  {$ifdef DEBUG}
    Assert (flush <> Z_NO_FLUSH, 'no flush?');
  {$endif}

  if s.match_available then begin
    {$ifdef DEBUG}
      Tracevv(char8(s.window^[s.strstart-1]));
    {$endif}
    _tr_tally (s, 0, s.window^[s.strstart-1]);
    s.match_available := false;
  end;

  FLUSH_BLOCK_ONLY(s, flush = Z_FINISH);
  if s.strm^.avail_out=0 then begin
    if flush=Z_FINISH then deflate_slow := finish_started
    else deflate_slow := need_more;
    exit;
  end;

  if flush = Z_FINISH then deflate_slow := finish_done
  else deflate_slow := block_done;

end;


{Values for max_lazy_match, good_match and max_chain_length, depending on
the desired pack level (0..9). The values given below have been tuned to
exclude worst case performance for pathological files. Better values may be
found for specific files.}

type
  config = record
             good_length: ush; {reduce lazy search above this match length}
             max_lazy   : ush; {do not perform lazy search above this match length}
             nice_length: ush; {quit search above this match length}
             max_chain  : ush;
             func       : compress_func;
          end;
{$ifdef FPC_ProcVar}
  const
    configuration_table: array[0..10-1] of config = (
  {     good lazy nice chain}
  {0} (good_length:0;  max_lazy:0;   nice_length:0;   max_chain:0;    func:@deflate_stored),  {store only}
  {1} (good_length:4;  max_lazy:4;   nice_length:8;   max_chain:4;    func:@deflate_fast), {maximum speed, no lazy matches}
  {2} (good_length:4;  max_lazy:5;   nice_length:16;  max_chain:8;    func:@deflate_fast),
  {3} (good_length:4;  max_lazy:6;   nice_length:32;  max_chain:32;   func:@deflate_fast),

  {4} (good_length:4;  max_lazy:4;   nice_length:16;  max_chain:16;   func:@deflate_slow),  {lazy matches}
  {5} (good_length:8;  max_lazy:16;  nice_length:32;  max_chain:32;   func:@deflate_slow),
  {6} (good_length:8;  max_lazy:16;  nice_length:128; max_chain:128;  func:@deflate_slow),
  {7} (good_length:8;  max_lazy:32;  nice_length:128; max_chain:256;  func:@deflate_slow),
  {8} (good_length:32; max_lazy:128; nice_length:258; max_chain:1024; func:@deflate_slow),
  {9} (good_length:32; max_lazy:258; nice_length:258; max_chain:4096; func:@deflate_slow)); {maximum compression}
{$else}
  const
    configuration_table: array[0..10-1] of config = (
  {     good lazy nice chain}
  {0} (good_length:0;  max_lazy:0;   nice_length:0;   max_chain:0;    func:deflate_stored),  {store only}
  {1} (good_length:4;  max_lazy:4;   nice_length:8;   max_chain:4;    func:deflate_fast), {maximum speed, no lazy matches}
  {2} (good_length:4;  max_lazy:5;   nice_length:16;  max_chain:8;    func:deflate_fast),
  {3} (good_length:4;  max_lazy:6;   nice_length:32;  max_chain:32;   func:deflate_fast),

  {4} (good_length:4;  max_lazy:4;   nice_length:16;  max_chain:16;   func:deflate_slow),  {lazy matches}
  {5} (good_length:8;  max_lazy:16;  nice_length:32;  max_chain:32;   func:deflate_slow),
  {6} (good_length:8;  max_lazy:16;  nice_length:128; max_chain:128;  func:deflate_slow),
  {7} (good_length:8;  max_lazy:32;  nice_length:128; max_chain:256;  func:deflate_slow),
  {8} (good_length:32; max_lazy:128; nice_length:258; max_chain:1024; func:deflate_slow),
  {9} (good_length:32; max_lazy:258; nice_length:258; max_chain:4096; func:deflate_slow)); {maximum compression}
{$endif}

{Note: the deflate() code requires max_lazy >= MIN_MATCH and max_chain >= 4
For deflate_fast() (levels <= 3) good is ignored and lazy has a different meaning.}




{---------------------------------------------------------------------------}
procedure lm_init(var s: deflate_state);
  {-Initialize the "longest match" routines for a new zlib stream}
begin
  s.window_size := 2*ulg(s.w_size);
  {macro CLEAR_HASH(s);}
  s.head^[s.hash_size-1] := ZNIL;
  zmemzero(pBytef(s.head), unsigned(s.hash_size-1)*sizeof(s.head^[0]));

  {Set the default configuration parameters:}
  s.max_lazy_match   := configuration_table[s.level].max_lazy;
  s.good_match       := configuration_table[s.level].good_length;
  s.nice_match       := configuration_table[s.level].nice_length;
  s.max_chain_length := configuration_table[s.level].max_chain;

  s.strstart := 0;
  s.block_start := long(0);
  s.lookahead := 0;
  s.prev_length := MIN_MATCH-1;
  s.match_length := MIN_MATCH-1;
  s.match_available := false;
  s.ins_h := 0;
end;



{---------------------------------------------------------------------------}
function deflateInit2_(     var strm: z_stream;
                               level: int;
                              method: int;
                          windowBits: int;
                            memLevel: int;
                            strategy: int;
                       const version: str255;
                         stream_size: int): int;
var
  s: deflate_state_ptr;
  noheader: int;
  overlay: pushfArray;
  {We overlay pending_buf and d_buf+l_buf. This works since the average
  output size for (length,distance) codes is <= 24 bits.}
begin
  noheader := 0;
  if (version='') or (version[1]<>ZLIB_VERSION[1]) or (stream_size<>sizeof(z_stream)) then begin
    deflateInit2_ := Z_VERSION_ERROR;
    exit;
  end;
  {*we: strm is var so following code is not needed
  if strm=Z_NULL then begin
    deflateInit2_ := Z_STREAM_ERROR;
    exit;
  end;
  }

  {SetLength(strm.msg, 255);}
  strm.msg := '';
  if not Assigned(strm.zalloc) then begin
    {$ifdef FPC_ProcVar}
      strm.zalloc := @zcalloc;
    {$else}
      strm.zalloc := zcalloc;
    {$endif}
    strm.opaque := voidpf(0);
  end;
  if not Assigned(strm.zfree) then begin
    {$ifdef FPC_ProcVar}
      strm.zfree := @zcfree;
    {$else}
      strm.zfree := zcfree;
    {$endif}
  end;

  if (level  =  Z_DEFAULT_COMPRESSION) then
    {$ifdef FASTEST}
      level := 1;
    {$else}
      level := 6;
    {$endif}
  if windowBits<0 then begin
    {undocumented feature: suppress zlib header}
    noheader := 1;
    windowBits := -windowBits;
  end;

  if (memLevel < 1) or (memLevel > MAX_MEM_LEVEL) or (method <> Z_DEFLATED)
    or (windowBits < 9) or (windowBits > 15)           {*we 114}
    or (level < 0) or (level > 9)
    or (strategy < 0) or (strategy > Z_HUFFMAN_ONLY) then
  begin
    deflateInit2_ := Z_STREAM_ERROR;
    exit;
  end;

  s := deflate_state_ptr(Z_ALLOC(strm, 1, sizeof(deflate_state)));
  if s=Z_NULL then begin
    deflateInit2_ := Z_MEM_ERROR;
    exit;
  end;
  strm.state := s;


  s^.strm := @strm;

  s^.noheader := noheader;
  s^.w_bits := windowBits;
  s^.w_size := 1 shl s^.w_bits;
  s^.w_mask := s^.w_size - 1;

  s^.hash_bits := memLevel + 7;
  s^.hash_size := 1 shl s^.hash_bits;
  s^.hash_mask := s^.hash_size - 1;
  s^.hash_shift:= ((s^.hash_bits+MIN_MATCH-1) div MIN_MATCH);

  s^.window := pzByteArray(Z_ALLOC(strm, s^.w_size, 2*sizeof(byte)));
  s^.prev   := pzPosfArray(Z_ALLOC(strm, s^.w_size, sizeof(pos)));
  s^.head   := pzPosfArray(Z_ALLOC(strm, s^.hash_size, sizeof(pos)));

  s^.lit_bufsize := 1 shl (memLevel + 6); {16K elements by default}

  overlay := pushfArray(Z_ALLOC(strm, s^.lit_bufsize, sizeof(ush)+2));
  s^.pending_buf := pzByteArray(overlay);
  s^.pending_buf_size := ulg(s^.lit_bufsize) * (sizeof(ush)+Long(2));

  if (s^.window=Z_NULL) or (s^.prev=Z_NULL) or (s^.head=Z_NULL) or (s^.pending_buf=Z_NULL) then begin
    {ERR_MSG(Z_MEM_ERROR);}
    strm.msg := z_errmsg[z_errbase-Z_MEM_ERROR];
    deflateEnd(strm);
    deflateInit2_ := Z_MEM_ERROR;
    exit;
  end;
  s^.d_buf := pushfArray(@overlay^[s^.lit_bufsize div sizeof(ush)]);
  s^.l_buf := puchfArray(@s^.pending_buf^[(1+sizeof(ush))*s^.lit_bufsize]);

  s^.level := level;
  s^.strategy := strategy;
  s^.method := byte(method);

  deflateInit2_ := deflateReset(strm);
end;


{---------------------------------------------------------------------------}
function deflateInit2(  var strm: z_stream;
                           level: int;
                          method: int;
                      windowBits: int;
                        memLevel: int;
                        strategy: int): int;
begin
  deflateInit2 := deflateInit2_(strm, level, method, windowBits, memLevel,
                                strategy, ZLIB_VERSION, sizeof(z_stream));
end;


{---------------------------------------------------------------------------}
function deflateInit(var strm: z_stream; level: int): int;
begin
  deflateInit := deflateInit2_(strm, level, Z_DEFLATED, MAX_WBITS, DEF_MEM_LEVEL,
                               Z_DEFAULT_STRATEGY, ZLIB_VERSION, sizeof(z_stream));
end;


{---------------------------------------------------------------------------}
function deflateSetDictionary(var strm: z_stream; dictionary: pBytef; dictLength: uInt): int;
var
  s: deflate_state_ptr;
  length: uInt;
  n: uInt;
  hash_head: IPos;
var
  MAX_DIST: uInt;  {macro}
begin
  length := dictLength;
  hash_head := 0;
  s := deflate_state_ptr(strm.state);

  if (s=Z_NULL) or (dictionary=Z_NULL) or (s^.status<>INIT_STATE) then begin
    deflateSetDictionary := Z_STREAM_ERROR;
    exit;
  end;

  strm.adler := adler32(strm.adler, dictionary, dictLength);

  if length<MIN_MATCH then begin
    deflateSetDictionary := Z_OK;
    exit;
  end;

  MAX_DIST := (s^.w_size - MIN_LOOKAHEAD);
  if length>MAX_DIST then begin
    length := MAX_DIST;
    {$ifndef USE_DICT_HEAD}
      inc(dictionary, dictLength - length);  {use the tail of the dictionary}
    {$endif}
  end;

  zmemcpy(pBytef(s^.window), dictionary, length);
  s^.strstart := length;
  s^.block_start := long(length);

  {Insert all strings in the hash table (except for the last two bytes).
  s^.lookahead stays null, so s^.ins_h will be recomputed at the next
  call of fill_window.}

  s^.ins_h := s^.window^[0];
  {UPDATE_HASH(s, s^.ins_h, s^.window[1]);}
  s^.ins_h := ((s^.ins_h shl s^.hash_shift) xor (s^.window^[1])) and s^.hash_mask;

  for n := 0 to length - MIN_MATCH do INSERT_STRING(s^, n, hash_head);
  deflateSetDictionary := Z_OK;
end;


{---------------------------------------------------------------------------}
function deflateReset (var strm: z_stream): int;
var
  s: deflate_state_ptr;
begin
  if (strm.state = Z_NULL) or (not Assigned(strm.zalloc)) or (not Assigned(strm.zfree)) then begin
    deflateReset := Z_STREAM_ERROR;
    exit;
  end;

  strm.total_out := 0;
  strm.total_in := 0;
  strm.msg := '';      {use zfree if we ever allocate msg dynamically}
  strm.data_type := Z_UNKNOWN;

  s := deflate_state_ptr(strm.state);
  s^.pending := 0;
  s^.pending_out := pBytef(s^.pending_buf);

  if s^.noheader<0 then s^.noheader := 0; {was set to -1 by deflate(..., Z_FINISH);}

  if s^.noheader<>0 then s^.status := BUSY_STATE
  else s^.status := INIT_STATE;

  strm.adler := 1;
  s^.last_flush := Z_NO_FLUSH;

  _tr_init(s^);
  lm_init(s^);

  deflateReset := Z_OK;
end;


{---------------------------------------------------------------------------}
function deflateParams(var strm: z_stream; level: int; strategy: int): int;
  {-Dynamically update the compression level and compression strategy.}
var
  s: deflate_state_ptr;
  func: compress_func;
  err: int;
begin
  err := Z_OK;
  if strm.state=Z_NULL then begin
    deflateParams := Z_STREAM_ERROR;
    exit;
  end;

  s := deflate_state_ptr(strm.state);

  if level=Z_DEFAULT_COMPRESSION then level := 6;

  if (level<0) or (level>9) or (strategy<0) or (strategy>Z_HUFFMAN_ONLY) then begin
    deflateParams := Z_STREAM_ERROR;
    exit;
  end;
  func := configuration_table[s^.level].func;

  if (@func<>@configuration_table[level].func) and (strm.total_in<>0) then begin
    {Flush the last buffer:}
    err := deflate(strm, Z_PARTIAL_FLUSH);
  end;

  if s^.level<>level then begin
    s^.level := level;
    s^.max_lazy_match   := configuration_table[level].max_lazy;
    s^.good_match       := configuration_table[level].good_length;
    s^.nice_match       := configuration_table[level].nice_length;
    s^.max_chain_length := configuration_table[level].max_chain;
  end;
  s^.strategy := strategy;
  deflateParams := err;
end;



{---------------------------------------------------------------------------}
procedure putShortMSB (var s: deflate_state; b: uInt);
  {Put a short in the pending buffer. The 16-bit value is put in MSB order.
  IN assertion: the stream state is correct and there is enough room in
  pending_buf.}
begin
  s.pending_buf^[s.pending] := byte(b shr 8);
  inc(s.pending);
  s.pending_buf^[s.pending] := byte(b and $ff);
  inc(s.pending);
end;


{---------------------------------------------------------------------------}
function deflate(var strm: z_stream; flush: int): int;
var
  old_flush: int; {value of flush param for previous deflate call}
  s: deflate_state_ptr;
var
  header: uInt;
  level_flags: uInt;
  bstate: block_state;
begin
  if (strm.state=Z_NULL) or (flush>Z_FINISH) or (flush<0) then begin
    deflate := Z_STREAM_ERROR;
    exit;
  end;
  s := deflate_state_ptr(strm.state);

  if (strm.next_out = Z_NULL) or
     ((strm.next_in = Z_NULL) and (strm.avail_in <> 0)) or
     ((s^.status = FINISH_STATE) and (flush <> Z_FINISH)) then
  begin
    strm.msg := z_errmsg[z_errbase - Z_STREAM_ERROR];
    deflate := Z_STREAM_ERROR;
    exit;
  end;

  if strm.avail_out=0 then begin
    strm.msg := z_errmsg[z_errbase - Z_BUF_ERROR];
    deflate := Z_BUF_ERROR;
    exit;
  end;

  s^.strm := @strm; {just in case}
  old_flush := s^.last_flush;
  s^.last_flush := flush;

  {write the zlib header}
  if s^.status=INIT_STATE then begin
    header := (Z_DEFLATED + ((s^.w_bits-8) shl 4)) shl 8;
    level_flags := (s^.level-1) shr 1;
    if level_flags>3 then level_flags := 3;
    header := header or (level_flags shl 6);
    if s^.strstart<>0 then header := header or PRESET_DICT;
    inc(header, 31 - (header mod 31));

    s^.status := BUSY_STATE;
    putShortMSB(s^, header);

    {Save the adler32 of the preset dictionary:}
    if s^.strstart<>0 then begin
      putShortMSB(s^, uInt(strm.adler shr 16));
      putShortMSB(s^, uInt(strm.adler and $ffff));
    end;
    strm.adler := long(1);
  end;

  {Flush as much pending output as possible}
  if s^.pending<>0 then begin
    flush_pending(strm);
    if strm.avail_out=0 then begin
      {Since avail_out is 0, deflate will be called again with
      more output space, but possibly with both pending and
      avail_in equal to zero. There won't be anything to do,
      but this is not an error situation so make sure we
      return OK instead of BUF_ERROR at next call of deflate:}
      s^.last_flush := -1;
      deflate := Z_OK;
      exit;
    end;

    {Make sure there is something to do and avoid duplicate consecutive
    flushes. For repeated and useless calls with Z_FINISH, we keep
    returning Z_STREAM_END instead of Z_BUFF_ERROR.}
  end
  else if (strm.avail_in=0) and (flush<=old_flush) and (flush<>Z_FINISH) then begin
    {ERR_RETURN(strm^, Z_BUF_ERROR);}
    strm.msg := z_errmsg[z_errbase - Z_BUF_ERROR];
    deflate := Z_BUF_ERROR;
    exit;
  end;

  {User must not provide more input after the first FINISH:}
  if (s^.status=FINISH_STATE) and (strm.avail_in<>0) then begin
    {ERR_RETURN(strm^, Z_BUF_ERROR);}
    strm.msg := z_errmsg[z_errbase - Z_BUF_ERROR];
    deflate := Z_BUF_ERROR;
    exit;
  end;

  {Start a new block or continue the current one.}
  if (strm.avail_in <> 0) or (s^.lookahead <> 0)
    or ((flush <> Z_NO_FLUSH) and (s^.status <> FINISH_STATE)) then
  begin
    bstate := configuration_table[s^.level].func(s^, flush);

    if (bstate=finish_started) or (bstate=finish_done) then s^.status := FINISH_STATE;

    if (bstate=need_more) or (bstate=finish_started) then begin
      if strm.avail_out=0 then s^.last_flush := -1; {avoid BUF_ERROR next call, see above}
      deflate := Z_OK;
      exit;
      { If flush != Z_NO_FLUSH && avail_out == 0, the next call
        of deflate should use the same flush parameter to make sure
        that the flush is complete. So we don't have to output an
        empty block here, this will be done at next call. This also
        ensures that for a very small output buffer, we emit at most
         one empty block.}
    end;
    if bstate=block_done then begin
      if flush=Z_PARTIAL_FLUSH then _tr_align(s^)
      else begin
        {FULL_FLUSH or SYNC_FLUSH}
        _tr_stored_block(s^, pcharf(nil), Long(0), false);

        {For a full flush, this empty block will be recognized
        as a special marker by inflate_sync().}
        if flush=Z_FULL_FLUSH then begin
          {macro CLEAR_HASH(s);}             {forget history}
          s^.head^[s^.hash_size-1] := ZNIL;
          zmemzero(pBytef(s^.head), unsigned(s^.hash_size-1)*sizeof(s^.head^[0]));
        end;
      end;

      flush_pending(strm);
      if strm.avail_out=0 then begin
        s^.last_flush := -1; {avoid BUF_ERROR at next call, see above}
        deflate := Z_OK;
        exit;
      end;

    end;
  end;

  {$ifdef DEBUG}
    Assert(strm.avail_out > 0, 'bug2');
  {$endif}

  if flush<>Z_FINISH then begin
    deflate := Z_OK;
    exit;
  end;

  if s^.noheader<>0 then begin
    deflate := Z_STREAM_END;
    exit;
  end;

  {write the zlib trailer (adler32)}
  putShortMSB(s^, uInt(strm.adler shr 16));
  putShortMSB(s^, uInt(strm.adler and $ffff));
  flush_pending(strm);
  {If avail_out is zero, the application will call deflate again to flush the rest.}

  s^.noheader := -1; {write the trailer only once!}
  if s^.pending<>0 then deflate := Z_OK
  else deflate := Z_STREAM_END;
end;


{---------------------------------------------------------------------------}
function deflateEnd (var strm: z_stream): int;
  {-All dynamically allocated data structures for this stream are freed.}
var
  status: int;
  s: deflate_state_ptr;
begin
  if strm.state = Z_NULL then begin
    deflateEnd := Z_STREAM_ERROR;
    exit;
  end;

  s := deflate_state_ptr(strm.state);
  status := s^.status;
  if (status<>INIT_STATE) and (status<>BUSY_STATE) and (status<>FINISH_STATE) then begin
    deflateEnd := Z_STREAM_ERROR;
    exit;
  end;

  {Deallocate in reverse order of allocations:}
  TRY_FREE(strm, s^.pending_buf);
  TRY_FREE(strm, s^.head);
  TRY_FREE(strm, s^.prev);
  TRY_FREE(strm, s^.window);

  Z_FREE(strm, s);
  strm.state := Z_NULL;

  if status = BUSY_STATE then deflateEnd := Z_DATA_ERROR
  else deflateEnd := Z_OK;
end;



{---------------------------------------------------------------------------}
function deflateCopy (dest, source: z_streamp): int;
  {-Copy the source state to the destination state.
  To simplify the source, this is not supported for 16-bit MSDOS (which
  doesn't have enough memory anyway to duplicate compression states).}
{$ifndef MAXSEG_64K}
  var
    ds: deflate_state_ptr;
    ss: deflate_state_ptr;
    overlay: pushfArray;
{$endif}
begin
  {$ifdef MAXSEG_64K}
    deflateCopy := Z_STREAM_ERROR;
    exit;
  {$else}
    if (source=Z_NULL) or (dest=Z_NULL) or (source^.state=Z_NULL) then begin
      deflateCopy := Z_STREAM_ERROR;
      exit;
    end;
    ss := deflate_state_ptr(source^.state);
    dest^ := source^;

    ds := deflate_state_ptr(Z_ALLOC(dest^, 1, sizeof(deflate_state)));
    if ds=Z_NULL then begin
      deflateCopy := Z_MEM_ERROR;
      exit;
    end;
    dest^.state := ds;
    ds^ := ss^;
    ds^.strm := dest;

    ds^.window := pzByteArray(Z_ALLOC(dest^, ds^.w_size, 2*sizeof(byte)));
    ds^.prev   := pzPosfArray(Z_ALLOC(dest^, ds^.w_size, sizeof(pos)));
    ds^.head   := pzPosfArray(Z_ALLOC(dest^, ds^.hash_size, sizeof(pos)));
    overlay    := pushfArray(Z_ALLOC(dest^, ds^.lit_bufsize, sizeof(ush)+2));
    ds^.pending_buf := pzByteArray (overlay);

    if (ds^.window=Z_NULL) or (ds^.prev=Z_NULL) or (ds^.head=Z_NULL) or (ds^.pending_buf=Z_NULL) then begin
      deflateEnd (dest^);
      deflateCopy := Z_MEM_ERROR;
      exit;
    end;
    {following zmemcpy do not work for 16-bit MSDOS}
    zmemcpy(pBytef(ds^.window), pBytef(ss^.window), ds^.w_size * 2 * sizeof(byte));
    zmemcpy(pBytef(ds^.prev), pBytef(ss^.prev), ds^.w_size * sizeof(pos));
    zmemcpy(pBytef(ds^.head), pBytef(ss^.head), ds^.hash_size * sizeof(pos));
    zmemcpy(pBytef(ds^.pending_buf), pBytef(ss^.pending_buf), uInt(ds^.pending_buf_size));

    ds^.pending_out := @ds^.pending_buf^[ptr2int(ss^.pending_out) - ptr2int(ss^.pending_buf)];
    ds^.d_buf := pushfArray(@overlay^[ds^.lit_bufsize div sizeof(ush)]);
    ds^.l_buf := puchfArray(@ds^.pending_buf^[(1+sizeof(ush))*ds^.lit_bufsize]);

    ds^.l_desc.dyn_tree := tree_ptr(@ds^.dyn_ltree);
    ds^.d_desc.dyn_tree := tree_ptr(@ds^.dyn_dtree);
    ds^.bl_desc.dyn_tree := tree_ptr(@ds^.bl_tree);

    deflateCopy := Z_OK;
{$endif}
end;

begin
  deflate_copyright := ' deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly ';    {*we 114}
end.
