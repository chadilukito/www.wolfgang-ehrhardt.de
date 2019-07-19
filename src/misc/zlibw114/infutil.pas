unit infutil;

(************************************************************************
  types and macros/functions common to blocks and codes

  Copyright (C) 1995-1998 Mark Adler

   WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change.

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:
  Feb 2002
    - Source code reformating/reordering
    - Removed dead C macro code
    - "_" for enum types (conflicts with case insensitive globals)
  Mar 2005
    - Code cleanup for WWW upload
  ------------------------------------------------------------------------

*************************************************************************)


interface

{$I zconf.inc}

uses
  zlibh;


type
  pInflate_huft = ^inflate_huft;
  inflate_huft  = record
                    Exop,        {number of extra bits or operation}
                    bits: byte;  {number of bits in this code or subcode}
                    base: uInt;  {literal, length base, or distance base or table offset}
                  end;

type
  huft_field = array[0..(MaxMemBlock div sizeof(inflate_huft))-1] of inflate_huft;
  huft_ptr = ^huft_field;
type
  ppInflate_huft = ^pInflate_huft;

type
  inflate_codes_mode = ( {waiting for "i:"=input, "o:"=output, "x:"=nothing}
        _START,    {x: set up for LEN}
        _LEN,      {i: get length/literal/eob next}
        _LENEXT,   {i: getting length extra (have base)}
        _DIST,     {i: get distance next}
        _DISTEXT,  {i: getting distance extra}
        _COPY,     {o: copying bytes in window, waiting for space}
        _LIT,      {o: got literal, waiting for output space}
        _WASH,     {o: got eob, possibly still output waiting}
        _ZEND,     {x: got eob and all data flushed}
        _BADCODE); {x: got error}

{inflate codes private state}
type
  pInflate_codes_state = ^inflate_codes_state;
  inflate_codes_state = record

    mode: inflate_codes_mode;        {current inflate_codes mode}

    {mode dependent information}
    len: uInt;
    sub: record                      {submode}
           case byte of
             0: (code: record                 {if LEN or DIST, where in tree}
                         tree: pInflate_huft; {pointer into tree}
                         need: uInt;          {bits needed}
                       end);
             1: (lit : uInt);                 {if LIT, literal}
             2: (copy: record                 {if EXT or COPY, where and how much}
                         get: uInt;           {bits to get for extra}
                         dist: uInt;          {distance back to copy from}
                       end);
        end;

    {mode independent information}
    lbits: byte;                     {ltree bits decoded per branch}
    dbits: byte;                     {dtree bits decoder per branch}
    ltree: pInflate_huft;            {literal/length/eob tree}
    dtree: pInflate_huft;            {distance tree}
  end;

type
  check_func = function(check: uLong; buf: pBytef; len: uInt): uLong;
type
  inflate_block_mode =
     (_ZTYPE,    {get type bits (3, including end bit)}
      _LENS,     {get lengths for stored}
      _STORED,   {processing stored block}
      _TABLE,    {get table lengths}
      _BTREE,    {get bit lengths tree for a dynamic block}
      _DTREE,    {get length, distance trees for a dynamic block}
      _CODES,    {processing fixed or dynamic block}
      _DRY,      {output remaining window bytes}
      _BLKDONE,  {finished last block, done}
      _BLKBAD);  {got a data error--stuck here}


type
  zuIntArray = array[0..(MaxMemBlock div sizeof(uInt))-1] of uInt;
  PuIntArray = ^zuIntArray;

type
  pInflate_blocks_state = ^inflate_blocks_state;

  {inflate blocks semi-private state}
  inflate_blocks_state = record

    mode: inflate_block_mode;     {current inflate_block mode}

    {mode dependent information}
    sub: record                  {submode}
    case byte of
      0: (left: uInt);                 {if STORED, bytes left to copy}
      1: (trees: record                {if DTREE, decoding info for trees}
                   table: uInt;        {table lengths (14 bits)}
                   index: uInt;        {index into blens (or border)}
                   blens: PuIntArray;  {bit lengths of codes}
                   bb: uInt;           {bit length tree depth}
                   tb: pInflate_huft;  {bit length decoding tree}
                 end);
      2: (decode: record               {if CODES, current state}
                    tl: pInflate_huft;
                    td: pInflate_huft; {trees to free}
                    codes: pInflate_codes_state;
                  end);
    end;
    last: boolean;               {true if this block is the last block}

    {mode independent information}
    bitk: uInt;            {bits in bit buffer}
    bitb: uLong;           {bit buffer}
    hufts: huft_ptr;       {pInflate_huft;}  {single malloc for tree space}
    window: pBytef;        {sliding window}
    zend: pBytef;          {one byte after sliding window}
    read: pBytef;          {window read pointer}
    write: pBytef;         {window write pointer}
    checkfn: check_func;   {check function}
    check: uLong;          {check on output}
  end;

type
  inflate_mode = (
      _METHOD,   {waiting for method byte}
      _FLAG,     {waiting for flag byte}
      _DICT4,    {four dictionary check bytes to go}
      _DICT3,    {three dictionary check bytes to go}
      _DICT2,    {two dictionary check bytes to go}
      _DICT1,    {one dictionary check byte to go}
      _DICT0,    {waiting for inflateSetDictionary}
      _BLOCKS,   {decompressing blocks}
      _CHECK4,   {four check bytes to go}
      _CHECK3,   {three check bytes to go}
      _CHECK2,   {two check bytes to go}
      _CHECK1,   {one check byte to go}
      _DONE,     {finished check, done}
      _BAD);     {got an error--stay here}

{inflate private state}
type
  pInternal_state = ^internal_state; {or point to a deflate_state record}
  internal_state = record

     mode: inflate_mode;  {current inflate mode}

     {mode dependent information}
     sub: record          {submode}
            case byte of
            0: (method: uInt);         {if FLAGS, method byte}
            1: (check : record         {if CHECK, check values to compare}
                          was: uLong;  {computed check value}
                          need: uLong; {stream check value}
                        end);
            2:(marker:  uInt);         {if BAD, inflateSync's marker bytes count}
          end;

     {mode independent information}
     nowrap: boolean;      {flag for no wrapper}
     wbits: uInt;          {log2(window size)  (8..15, defaults to 15)}
     blocks: pInflate_blocks_state;    {current inflate_blocks state}
   end;


function inflate_flush(var s: inflate_blocks_state; var z: z_stream; r: int): int;
  {-copy as much as possible from the sliding window to the output area}

{And'ing with mask[n] masks the lower n bits}
const
  inflate_mask: array[0..17-1] of uInt = (
    $0000, $0001, $0003, $0007, $000f, $001f, $003f, $007f, $00ff,
    $01ff, $03ff, $07ff, $0fff, $1fff, $3fff, $7fff, $ffff);


implementation

uses
  zutil;


{---------------------------------------------------------------------------}
function inflate_flush(var s: inflate_blocks_state; var z: z_stream; r: int): int;
  {-copy as much as possible from the sliding window to the output area}
var
  n: uInt;
  p: pBytef;
  q: pBytef;
begin
  {local copies of source and destination pointers}
  p := z.next_out;
  q := s.read;

  {compute number of bytes to copy as far as end of window}
  if ptr2int(q) <= ptr2int(s.write) then n := uInt(ptr2int(s.write) - ptr2int(q))
  else n := uInt(ptr2int(s.zend) - ptr2int(q));
  if n>z.avail_out then n := z.avail_out;
  if (n<>0) and (r=Z_BUF_ERROR) then r := Z_OK;

  {update counters}
  dec(z.avail_out, n);
  inc(z.total_out, n);

  {update check information}
  if Assigned(s.checkfn) then begin
    s.check := s.checkfn(s.check, q, n);
    z.adler := s.check;
  end;

  {copy as far as end of window}
  zmemcpy(p, q, n);
  inc(p, n);
  inc(q, n);

  {see if more to copy at beginning of window}
  if q=s.zend then begin
    {wrap pointers}
    q := s.window;
    if s.write=s.zend then s.write := s.window;

    {compute bytes to copy}
    n := uInt(ptr2int(s.write) - ptr2int(q));
    if n>z.avail_out then n := z.avail_out;
    if (n<>0) and (r=Z_BUF_ERROR) then r := Z_OK;

    {update counters}
    dec(z.avail_out, n);
    inc(z.total_out, n);

    {update check information}
    if Assigned(s.checkfn) then begin
      s.check := s.checkfn(s.check, q, n);
      z.adler := s.check;
    end;

    {copy}
    zmemcpy(p, q, n);
    inc(p, n);
    inc(q, n);
  end;


  {update pointers}
  z.next_out := p;
  s.read := q;

  {done}
  inflate_flush := r;
end;

end.
