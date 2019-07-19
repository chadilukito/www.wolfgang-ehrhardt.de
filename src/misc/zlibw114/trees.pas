unit trees;

{$T-}

(************************************************************************

  trees.c -- output deflated data using Huffman coding
  Copyright (C) 1995-1998 Jean-loup Gailly

  ------------------------------------------------------------------------
  ALGORITHM

  The "deflation" process uses several Huffman trees. The more common source
  values are represented by shorter bit sequences.

  Each code tree is stored in a compressed form which is itself
  a Huffman encoding of the lengths of all the code strings (in
  ascending order by source values).  The actual code strings are
  reconstructed from the lengths in the inflate process, as described
  in the deflate specification.

   REFERENCES

       Deutsch, L.P.,"'Deflate' Compressed Data Format Specification".
       Available in ftp.uu.net:/pub/archiving/zip/doc/deflate-1.1.doc

       Storer, James A.
           Data Compression:  Methods and Theory, pp. 49-50.
           Computer Science Press, 1988.  ISBN 0-7167-8156-5.

       Sedgewick, R.
           Algorithms, p290.
           Addison-Wesley, 1983. ISBN 0-201-06672-6.
  ------------------------------------------------------------------------

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Aug 2000
    - ZLIB 113 changes
  Feb 2002
    - Source code reformating/reordering
    - $ifdefs ORG_DEBUG, GEN_TREES_H, DUMP_BL_TREE,
      FORCE_STORED, FORCE_STATIC removed
    - Replaced printf fragments in trace call by IntToStr
  Mar 2005
    - Code cleanup for WWW upload
  Apr 2005
    - uses zutil if debug
  May 2005
    - Trace: use #13#10 like C original
    - Debug: removed MAX_DIST in _tr_tally
    - Debug: Long type cast in compress_block
  Dec 2006
    - Debug: fixed old paszlib bug in copy_block
  Jul 2009
    - D12 fixes
  ------------------------------------------------------------------------

*************************************************************************)


interface

{$I zconf.inc}

uses
  zlibh;

const
  LENGTH_CODES = 29;            {number of length codes, not counting the special END_BLOCK code}
  LITERALS     = 256;           {number of literal bytes 0..255}
  D_CODES      = 30;            {number of distance codes}
  BL_CODES     = 19;            {number of codes used to transfer the bit lengths}
  MAX_BITS     = 15;            {All codes must not exceed MAX_BITS bits}
  L_CODES      = (LITERALS+1+LENGTH_CODES); {number of Literal or Length codes, including the END_BLOCK code}
  HEAP_SIZE    = (2*L_CODES+1); {maximum heap size}

const
  INIT_STATE   =  42;             {Stream status}
  BUSY_STATE   = 113;
  FINISH_STATE = 666;


{Data structure describing a single value and its code string.}
type
  ct_data = record
              fc: record
                     case byte of
                     0: (freq: ush);       {frequency count}
                     1: (code: ush);       {bit string}
                   end;
              dl: record
                     case byte of
                     0: (dad: ush);        {father node in Huffman tree}
                     1: (len: ush);        {length of bit string}
                   end;
            end;


type
  ltree_type = array[0..HEAP_SIZE-1] of ct_data;    {literal and length tree}
  dtree_type = array[0..2*D_CODES+1-1] of ct_data;  {distance tree}
  htree_type = array[0..2*BL_CODES+1-1] of ct_data; {Huffman tree for bit lengths}

  {generic tree type}
  tree_type  = array[0..(MaxMemBlock div sizeof(ct_data))-1] of ct_data;
  tree_ptr   = ^tree_type;

type
  static_tree_desc_ptr = ^static_tree_desc;
  static_tree_desc =  record
                        static_tree: tree_ptr;    {static tree or nil}
                        extra_bits : pzIntfArray; {extra bits for each code or nil}
                        extra_base : int;         {base index for extra_bits}
                        elems      : int;         {max number of elements in the tree}
                        max_length : int;         {max bit length for the codes}
                      end;
  tree_desc       = record
                      dyn_tree : tree_ptr;         {the dynamic tree}
                      max_code : int;              {largest code with non zero frequency}
                      stat_desc: static_tree_desc_ptr; {the corresponding static tree}
                    end;

{A Pos is an index in the character window. We use short instead of int to
save space in the various tables. IPos is used only for parameter passing.}

type
  Pos   = ush;
  Posf  = Pos; {far}
  IPos  = uInt;
  pPosf = ^Posf;

  zPosfArray = array[0..(MaxMemBlock div sizeof(Posf))-1] of Posf;
  pzPosfArray = ^zPosfArray;

type
  zuchfArray = zByteArray;
  puchfArray = ^zuchfArray;

type
  zushfArray = array[0..(MaxMemBlock div sizeof(ushf))-1] of ushf;
  pushfArray = ^zushfArray;

type
  deflate_state_ptr = ^deflate_state;
  deflate_state = record
    strm: z_streamp;          {pointer back to this zlib stream}
    status: int;              {as the name implies}
    pending_buf: pzByteArray; {output still pending}
    pending_buf_size: ulg;    {size of pending_buf}
    pending_out: pBytef;      {next pending byte to output to the stream}
    pending: int;             {nb of bytes in the pending buffer}
    noheader: int;            {suppress zlib header and adler32}
    data_type: byte;          {UNKNOWN, BINARY or ASCII}
    method: byte;             {STORED (for zip only) or DEFLATED}
    last_flush: int;          {value of flush param for previous deflate call}
                               {used by deflate.pas:}
    w_size: uInt;             {LZ77 window size (32K by default)}
    w_bits: uInt;             {log2(w_size)  (8..16)}
    w_mask: uInt;             {w_size - 1}

    window: pzByteArray;
    {Sliding window. Input bytes are read into the second half of the window,
     and move to the first half later to keep a dictionary of at least wSize
     bytes. With this organization, matches are limited to a distance of
     wSize-MAX_MATCH bytes, but this ensures that IO is always
     performed with a length multiple of the block size. Also, it limits
     the window size to 64K, which is quite useful on MSDOS.
     To do: use the user input buffer as sliding window.}

    window_size: ulg;
    {Actual size of window: 2*wSize, except when the user input buffer
      is directly used as sliding window.}

    prev: pzPosfArray;
    {Link to older string with same hash index. To limit the size of this
      array to 64K, this link is maintained only for the last 32K strings.
      An index in this array is thus a window index modulo 32K.}

    head: pzPosfArray;    {Heads of the hash chains or nil.}

    ins_h: uInt;          {hash index of string to be inserted}
    hash_size: uInt;      {number of elements in hash table}
    hash_bits: uInt;      {log2(hash_size)}
    hash_mask: uInt;      {hash_size-1}

    hash_shift: uInt;
    {Number of bits by which ins_h must be shifted at each input
      step. It must be such that after MIN_MATCH steps, the oldest
      byte no longer takes part in the hash key, that is:
        hash_shift * MIN_MATCH >= hash_bits    }

    block_start: long;
    {Window position at the beginning of the current output block. Gets
      negative when the window is moved backwards.}

    match_length: uInt;           {length of best match}
    prev_match: IPos;             {previous match}
    match_available: boolean;     {set if previous match exists}
    strstart: uInt;               {start of string to insert}
    match_start: uInt;            {start of matching string}
    lookahead: uInt;              {number of valid bytes ahead in window}

    prev_length: uInt;
    {Length of the best match at previous step. Matches not greater than this
     are discarded. This is used in the lazy match evaluation.}

    max_chain_length: uInt;
    {To speed up deflation, hash chains are never searched beyond this
     length.  A higher limit improves compression ratio but degrades the
     speed.}

    {moved to the end because Borland Pascal won't accept the following:
    max_lazy_match: uInt;
    max_insert_length: uInt absolute max_lazy_match;}

    level: int;    {compression level (1..9)}
    strategy: int; {favor or force Huffman coding}

    good_match: uInt;
    {Use a faster search when the previous match is longer than this}

    nice_match: int; {Stop searching when current match exceeds this}

                {used by trees.pas:}
    {Didn't use ct_data typedef below to supress compiler warning}
    dyn_ltree: ltree_type;    {literal and length tree}
    dyn_dtree: dtree_type;  {distance tree}
    bl_tree: htree_type;   {Huffman tree for bit lengths}

    l_desc: tree_desc;                {desc. for literal tree}
    d_desc: tree_desc;                {desc. for distance tree}
    bl_desc: tree_desc;               {desc. for bit length tree}

    bl_count: array[0..MAX_BITS+1-1] of ush;
    {number of codes at each bit length for an optimal tree}

    heap: array[0..2*L_CODES+1-1] of int; {heap used to build the Huffman trees}
    heap_len: int;                   {number of elements in the heap}
    heap_max: int;                   {element of largest frequency}
    {The sons of heap[n] are heap[2*n] and heap[2*n+1]. heap[0] is not used.
      The same heap array is used to build all trees.}

    depth: array[0..2*L_CODES+1-1] of uch;
    {Depth of each subtree used as tie breaker for trees of equal frequency}


    l_buf: puchfArray;       {buffer for literals or lengths}

    lit_bufsize: uInt;
    {Size of match buffer for literals/lengths.  There are 4 reasons for
     limiting lit_bufsize to 64K:
       - frequencies can be kept in 16 bit counters
       - if compression is not successful for the first block, all input
         data is still in the window so we can still emit a stored block even
         when input comes from standard input.  (This can also be done for
         all blocks if lit_bufsize is not greater than 32K.)
       - if compression is not successful for a file smaller than 64K, we can
         even emit a stored file instead of a stored block (saving 5 bytes).
         This is applicable only for zip (not gzip or zlib).
       - creating new Huffman trees less frequently may not provide fast
         adaptation to changes in the input data statistics. (Take for
         example a binary file with poorly compressible code followed by
         a highly compressible string table.) Smaller buffer sizes give
         fast adaptation but have of course the overhead of transmitting
         trees more frequently.
       - I can't count above 4}


    last_lit: uInt;      {running index in l_buf}

    d_buf: pushfArray;
    {Buffer for distances. To simplify the code, d_buf and l_buf have
      the same number of elements. To use different lengths, an extra flag
      array would be necessary.}

    opt_len: ulg;        {bit length of current block with optimal trees}
    static_len: ulg;     {bit length of current block with static trees}
    matches: uInt;       {number of string matches in current block}
    last_eob_len: int;   {bit length of EOB code for last block}

{$ifdef DEBUG}
    compressed_len: ulg; {total bit length of compressed file} {*we 113}
    bits_sent: ulg;      {bit length of the compressed data}
{$endif}

    bi_buf: ush;
    {Output buffer. bits are inserted starting at the bottom (least
      significant bits).}

    bi_valid: int;
    {Number of valid bits in bi_buf.  All bits above the last valid bit
      are always zero.}

    case byte of
      0:(max_lazy_match: uInt);
      {Attempt to find a better match only when the current match is strictly
       smaller than this value. This mechanism is used only for compression
       levels >= 4.}

      1:(max_insert_length: uInt);
      {Insert new strings in the hash table only if the match length is not
       greater than this length. This saves time but degrades compression.
       max_insert_length is used only for compression levels <= 3.}
  end;


procedure _tr_init(var s: deflate_state);

function  _tr_tally(var s: deflate_state; dist: unsigned; lc: unsigned): boolean;

procedure _tr_flush_block(var s: deflate_state; buf: pcharf; stored_len: ulg; eof: boolean); {*we 113}

procedure _tr_stored_block(var s: deflate_state; buf: pcharf; stored_len: ulg; eof: boolean);

procedure _tr_align(var s: deflate_state);



implementation

{$ifdef debug}
uses zutil;
{$endif}

const
  DIST_CODE_LEN = 512; {see definition of array dist_code below}

{The static literal tree. Since the bit lengths are imposed, there is no
 need for the L_CODES extra codes used during heap construction. However
 The codes 286 and 287 are needed to build a canonical tree (see _tr_init
 below).}

const
  static_ltree: array[0..L_CODES+2-1] of ct_data = (
                   {fc:(freq cod) dl:(dad,len)}
                   (fc:(freq: 12);dl:(len: 8)), (fc:(freq:140);dl:(len: 8)),
                   (fc:(freq: 76);dl:(len: 8)), (fc:(freq:204);dl:(len: 8)),
                   (fc:(freq: 44);dl:(len: 8)), (fc:(freq:172);dl:(len: 8)),
                   (fc:(freq:108);dl:(len: 8)), (fc:(freq:236);dl:(len: 8)),
                   (fc:(freq: 28);dl:(len: 8)), (fc:(freq:156);dl:(len: 8)),
                   (fc:(freq: 92);dl:(len: 8)), (fc:(freq:220);dl:(len: 8)),
                   (fc:(freq: 60);dl:(len: 8)), (fc:(freq:188);dl:(len: 8)),
                   (fc:(freq:124);dl:(len: 8)), (fc:(freq:252);dl:(len: 8)),
                   (fc:(freq:  2);dl:(len: 8)), (fc:(freq:130);dl:(len: 8)),
                   (fc:(freq: 66);dl:(len: 8)), (fc:(freq:194);dl:(len: 8)),
                   (fc:(freq: 34);dl:(len: 8)), (fc:(freq:162);dl:(len: 8)),
                   (fc:(freq: 98);dl:(len: 8)), (fc:(freq:226);dl:(len: 8)),
                   (fc:(freq: 18);dl:(len: 8)), (fc:(freq:146);dl:(len: 8)),
                   (fc:(freq: 82);dl:(len: 8)), (fc:(freq:210);dl:(len: 8)),
                   (fc:(freq: 50);dl:(len: 8)), (fc:(freq:178);dl:(len: 8)),
                   (fc:(freq:114);dl:(len: 8)), (fc:(freq:242);dl:(len: 8)),
                   (fc:(freq: 10);dl:(len: 8)), (fc:(freq:138);dl:(len: 8)),
                   (fc:(freq: 74);dl:(len: 8)), (fc:(freq:202);dl:(len: 8)),
                   (fc:(freq: 42);dl:(len: 8)), (fc:(freq:170);dl:(len: 8)),
                   (fc:(freq:106);dl:(len: 8)), (fc:(freq:234);dl:(len: 8)),
                   (fc:(freq: 26);dl:(len: 8)), (fc:(freq:154);dl:(len: 8)),
                   (fc:(freq: 90);dl:(len: 8)), (fc:(freq:218);dl:(len: 8)),
                   (fc:(freq: 58);dl:(len: 8)), (fc:(freq:186);dl:(len: 8)),
                   (fc:(freq:122);dl:(len: 8)), (fc:(freq:250);dl:(len: 8)),
                   (fc:(freq:  6);dl:(len: 8)), (fc:(freq:134);dl:(len: 8)),
                   (fc:(freq: 70);dl:(len: 8)), (fc:(freq:198);dl:(len: 8)),
                   (fc:(freq: 38);dl:(len: 8)), (fc:(freq:166);dl:(len: 8)),
                   (fc:(freq:102);dl:(len: 8)), (fc:(freq:230);dl:(len: 8)),
                   (fc:(freq: 22);dl:(len: 8)), (fc:(freq:150);dl:(len: 8)),
                   (fc:(freq: 86);dl:(len: 8)), (fc:(freq:214);dl:(len: 8)),
                   (fc:(freq: 54);dl:(len: 8)), (fc:(freq:182);dl:(len: 8)),
                   (fc:(freq:118);dl:(len: 8)), (fc:(freq:246);dl:(len: 8)),
                   (fc:(freq: 14);dl:(len: 8)), (fc:(freq:142);dl:(len: 8)),
                   (fc:(freq: 78);dl:(len: 8)), (fc:(freq:206);dl:(len: 8)),
                   (fc:(freq: 46);dl:(len: 8)), (fc:(freq:174);dl:(len: 8)),
                   (fc:(freq:110);dl:(len: 8)), (fc:(freq:238);dl:(len: 8)),
                   (fc:(freq: 30);dl:(len: 8)), (fc:(freq:158);dl:(len: 8)),
                   (fc:(freq: 94);dl:(len: 8)), (fc:(freq:222);dl:(len: 8)),
                   (fc:(freq: 62);dl:(len: 8)), (fc:(freq:190);dl:(len: 8)),
                   (fc:(freq:126);dl:(len: 8)), (fc:(freq:254);dl:(len: 8)),
                   (fc:(freq:  1);dl:(len: 8)), (fc:(freq:129);dl:(len: 8)),
                   (fc:(freq: 65);dl:(len: 8)), (fc:(freq:193);dl:(len: 8)),
                   (fc:(freq: 33);dl:(len: 8)), (fc:(freq:161);dl:(len: 8)),
                   (fc:(freq: 97);dl:(len: 8)), (fc:(freq:225);dl:(len: 8)),
                   (fc:(freq: 17);dl:(len: 8)), (fc:(freq:145);dl:(len: 8)),
                   (fc:(freq: 81);dl:(len: 8)), (fc:(freq:209);dl:(len: 8)),
                   (fc:(freq: 49);dl:(len: 8)), (fc:(freq:177);dl:(len: 8)),
                   (fc:(freq:113);dl:(len: 8)), (fc:(freq:241);dl:(len: 8)),
                   (fc:(freq:  9);dl:(len: 8)), (fc:(freq:137);dl:(len: 8)),
                   (fc:(freq: 73);dl:(len: 8)), (fc:(freq:201);dl:(len: 8)),
                   (fc:(freq: 41);dl:(len: 8)), (fc:(freq:169);dl:(len: 8)),
                   (fc:(freq:105);dl:(len: 8)), (fc:(freq:233);dl:(len: 8)),
                   (fc:(freq: 25);dl:(len: 8)), (fc:(freq:153);dl:(len: 8)),
                   (fc:(freq: 89);dl:(len: 8)), (fc:(freq:217);dl:(len: 8)),
                   (fc:(freq: 57);dl:(len: 8)), (fc:(freq:185);dl:(len: 8)),
                   (fc:(freq:121);dl:(len: 8)), (fc:(freq:249);dl:(len: 8)),
                   (fc:(freq:  5);dl:(len: 8)), (fc:(freq:133);dl:(len: 8)),
                   (fc:(freq: 69);dl:(len: 8)), (fc:(freq:197);dl:(len: 8)),
                   (fc:(freq: 37);dl:(len: 8)), (fc:(freq:165);dl:(len: 8)),
                   (fc:(freq:101);dl:(len: 8)), (fc:(freq:229);dl:(len: 8)),
                   (fc:(freq: 21);dl:(len: 8)), (fc:(freq:149);dl:(len: 8)),
                   (fc:(freq: 85);dl:(len: 8)), (fc:(freq:213);dl:(len: 8)),
                   (fc:(freq: 53);dl:(len: 8)), (fc:(freq:181);dl:(len: 8)),
                   (fc:(freq:117);dl:(len: 8)), (fc:(freq:245);dl:(len: 8)),
                   (fc:(freq: 13);dl:(len: 8)), (fc:(freq:141);dl:(len: 8)),
                   (fc:(freq: 77);dl:(len: 8)), (fc:(freq:205);dl:(len: 8)),
                   (fc:(freq: 45);dl:(len: 8)), (fc:(freq:173);dl:(len: 8)),
                   (fc:(freq:109);dl:(len: 8)), (fc:(freq:237);dl:(len: 8)),
                   (fc:(freq: 29);dl:(len: 8)), (fc:(freq:157);dl:(len: 8)),
                   (fc:(freq: 93);dl:(len: 8)), (fc:(freq:221);dl:(len: 8)),
                   (fc:(freq: 61);dl:(len: 8)), (fc:(freq:189);dl:(len: 8)),
                   (fc:(freq:125);dl:(len: 8)), (fc:(freq:253);dl:(len: 8)),
                   (fc:(freq: 19);dl:(len: 9)), (fc:(freq:275);dl:(len: 9)),
                   (fc:(freq:147);dl:(len: 9)), (fc:(freq:403);dl:(len: 9)),
                   (fc:(freq: 83);dl:(len: 9)), (fc:(freq:339);dl:(len: 9)),
                   (fc:(freq:211);dl:(len: 9)), (fc:(freq:467);dl:(len: 9)),
                   (fc:(freq: 51);dl:(len: 9)), (fc:(freq:307);dl:(len: 9)),
                   (fc:(freq:179);dl:(len: 9)), (fc:(freq:435);dl:(len: 9)),
                   (fc:(freq:115);dl:(len: 9)), (fc:(freq:371);dl:(len: 9)),
                   (fc:(freq:243);dl:(len: 9)), (fc:(freq:499);dl:(len: 9)),
                   (fc:(freq: 11);dl:(len: 9)), (fc:(freq:267);dl:(len: 9)),
                   (fc:(freq:139);dl:(len: 9)), (fc:(freq:395);dl:(len: 9)),
                   (fc:(freq: 75);dl:(len: 9)), (fc:(freq:331);dl:(len: 9)),
                   (fc:(freq:203);dl:(len: 9)), (fc:(freq:459);dl:(len: 9)),
                   (fc:(freq: 43);dl:(len: 9)), (fc:(freq:299);dl:(len: 9)),
                   (fc:(freq:171);dl:(len: 9)), (fc:(freq:427);dl:(len: 9)),
                   (fc:(freq:107);dl:(len: 9)), (fc:(freq:363);dl:(len: 9)),
                   (fc:(freq:235);dl:(len: 9)), (fc:(freq:491);dl:(len: 9)),
                   (fc:(freq: 27);dl:(len: 9)), (fc:(freq:283);dl:(len: 9)),
                   (fc:(freq:155);dl:(len: 9)), (fc:(freq:411);dl:(len: 9)),
                   (fc:(freq: 91);dl:(len: 9)), (fc:(freq:347);dl:(len: 9)),
                   (fc:(freq:219);dl:(len: 9)), (fc:(freq:475);dl:(len: 9)),
                   (fc:(freq: 59);dl:(len: 9)), (fc:(freq:315);dl:(len: 9)),
                   (fc:(freq:187);dl:(len: 9)), (fc:(freq:443);dl:(len: 9)),
                   (fc:(freq:123);dl:(len: 9)), (fc:(freq:379);dl:(len: 9)),
                   (fc:(freq:251);dl:(len: 9)), (fc:(freq:507);dl:(len: 9)),
                   (fc:(freq:  7);dl:(len: 9)), (fc:(freq:263);dl:(len: 9)),
                   (fc:(freq:135);dl:(len: 9)), (fc:(freq:391);dl:(len: 9)),
                   (fc:(freq: 71);dl:(len: 9)), (fc:(freq:327);dl:(len: 9)),
                   (fc:(freq:199);dl:(len: 9)), (fc:(freq:455);dl:(len: 9)),
                   (fc:(freq: 39);dl:(len: 9)), (fc:(freq:295);dl:(len: 9)),
                   (fc:(freq:167);dl:(len: 9)), (fc:(freq:423);dl:(len: 9)),
                   (fc:(freq:103);dl:(len: 9)), (fc:(freq:359);dl:(len: 9)),
                   (fc:(freq:231);dl:(len: 9)), (fc:(freq:487);dl:(len: 9)),
                   (fc:(freq: 23);dl:(len: 9)), (fc:(freq:279);dl:(len: 9)),
                   (fc:(freq:151);dl:(len: 9)), (fc:(freq:407);dl:(len: 9)),
                   (fc:(freq: 87);dl:(len: 9)), (fc:(freq:343);dl:(len: 9)),
                   (fc:(freq:215);dl:(len: 9)), (fc:(freq:471);dl:(len: 9)),
                   (fc:(freq: 55);dl:(len: 9)), (fc:(freq:311);dl:(len: 9)),
                   (fc:(freq:183);dl:(len: 9)), (fc:(freq:439);dl:(len: 9)),
                   (fc:(freq:119);dl:(len: 9)), (fc:(freq:375);dl:(len: 9)),
                   (fc:(freq:247);dl:(len: 9)), (fc:(freq:503);dl:(len: 9)),
                   (fc:(freq: 15);dl:(len: 9)), (fc:(freq:271);dl:(len: 9)),
                   (fc:(freq:143);dl:(len: 9)), (fc:(freq:399);dl:(len: 9)),
                   (fc:(freq: 79);dl:(len: 9)), (fc:(freq:335);dl:(len: 9)),
                   (fc:(freq:207);dl:(len: 9)), (fc:(freq:463);dl:(len: 9)),
                   (fc:(freq: 47);dl:(len: 9)), (fc:(freq:303);dl:(len: 9)),
                   (fc:(freq:175);dl:(len: 9)), (fc:(freq:431);dl:(len: 9)),
                   (fc:(freq:111);dl:(len: 9)), (fc:(freq:367);dl:(len: 9)),
                   (fc:(freq:239);dl:(len: 9)), (fc:(freq:495);dl:(len: 9)),
                   (fc:(freq: 31);dl:(len: 9)), (fc:(freq:287);dl:(len: 9)),
                   (fc:(freq:159);dl:(len: 9)), (fc:(freq:415);dl:(len: 9)),
                   (fc:(freq: 95);dl:(len: 9)), (fc:(freq:351);dl:(len: 9)),
                   (fc:(freq:223);dl:(len: 9)), (fc:(freq:479);dl:(len: 9)),
                   (fc:(freq: 63);dl:(len: 9)), (fc:(freq:319);dl:(len: 9)),
                   (fc:(freq:191);dl:(len: 9)), (fc:(freq:447);dl:(len: 9)),
                   (fc:(freq:127);dl:(len: 9)), (fc:(freq:383);dl:(len: 9)),
                   (fc:(freq:255);dl:(len: 9)), (fc:(freq:511);dl:(len: 9)),
                   (fc:(freq:  0);dl:(len: 7)), (fc:(freq: 64);dl:(len: 7)),
                   (fc:(freq: 32);dl:(len: 7)), (fc:(freq: 96);dl:(len: 7)),
                   (fc:(freq: 16);dl:(len: 7)), (fc:(freq: 80);dl:(len: 7)),
                   (fc:(freq: 48);dl:(len: 7)), (fc:(freq:112);dl:(len: 7)),
                   (fc:(freq:  8);dl:(len: 7)), (fc:(freq: 72);dl:(len: 7)),
                   (fc:(freq: 40);dl:(len: 7)), (fc:(freq:104);dl:(len: 7)),
                   (fc:(freq: 24);dl:(len: 7)), (fc:(freq: 88);dl:(len: 7)),
                   (fc:(freq: 56);dl:(len: 7)), (fc:(freq:120);dl:(len: 7)),
                   (fc:(freq:  4);dl:(len: 7)), (fc:(freq: 68);dl:(len: 7)),
                   (fc:(freq: 36);dl:(len: 7)), (fc:(freq:100);dl:(len: 7)),
                   (fc:(freq: 20);dl:(len: 7)), (fc:(freq: 84);dl:(len: 7)),
                   (fc:(freq: 52);dl:(len: 7)), (fc:(freq:116);dl:(len: 7)),
                   (fc:(freq:  3);dl:(len: 8)), (fc:(freq:131);dl:(len: 8)),
                   (fc:(freq: 67);dl:(len: 8)), (fc:(freq:195);dl:(len: 8)),
                   (fc:(freq: 35);dl:(len: 8)), (fc:(freq:163);dl:(len: 8)),
                   (fc:(freq: 99);dl:(len: 8)), (fc:(freq:227);dl:(len: 8))  );


  {The static distance tree. (Actually a trivial tree since all lens use 5 bits.)}
  static_dtree: array[0..D_CODES-1] of ct_data = (
                   (fc:(freq: 0); dl:(len:5)), (fc:(freq:16); dl:(len:5)),
                   (fc:(freq: 8); dl:(len:5)), (fc:(freq:24); dl:(len:5)),
                   (fc:(freq: 4); dl:(len:5)), (fc:(freq:20); dl:(len:5)),
                   (fc:(freq:12); dl:(len:5)), (fc:(freq:28); dl:(len:5)),
                   (fc:(freq: 2); dl:(len:5)), (fc:(freq:18); dl:(len:5)),
                   (fc:(freq:10); dl:(len:5)), (fc:(freq:26); dl:(len:5)),
                   (fc:(freq: 6); dl:(len:5)), (fc:(freq:22); dl:(len:5)),
                   (fc:(freq:14); dl:(len:5)), (fc:(freq:30); dl:(len:5)),
                   (fc:(freq: 1); dl:(len:5)), (fc:(freq:17); dl:(len:5)),
                   (fc:(freq: 9); dl:(len:5)), (fc:(freq:25); dl:(len:5)),
                   (fc:(freq: 5); dl:(len:5)), (fc:(freq:21); dl:(len:5)),
                   (fc:(freq:13); dl:(len:5)), (fc:(freq:29); dl:(len:5)),
                   (fc:(freq: 3); dl:(len:5)), (fc:(freq:19); dl:(len:5)),
                   (fc:(freq:11); dl:(len:5)), (fc:(freq:27); dl:(len:5)),
                   (fc:(freq: 7); dl:(len:5)), (fc:(freq:23); dl:(len:5)) );

{Distance codes. The first 256 values correspond to the distances
  3 .. 258, the last 256 values correspond to the top 8 bits of
  the 15 bit distances.}
  _dist_code: array[0..DIST_CODE_LEN-1] of uch = (
                 0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,
                 8,  8,  8,  8,  8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9,
                10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
                11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
                12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
                13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
                14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
                14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
                14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
                14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
                15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
                15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
                15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
                15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
                 0,  0, 16, 17, 18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21,
                22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
                24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
                25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
                26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
                26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
                27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
                27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
                28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
                28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
                28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
                28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
                29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
                29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
                29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
                29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29  );

{length code for each normalized match length (0 == MIN_MATCH)}
  _length_code: array[0..MAX_MATCH-MIN_MATCH+1-1] of uch = (
                   0,  1,  2,  3,  4,  5,  6,  7,  8,  8,  9,  9, 10, 10,
                  11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14,
                  15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17,
                  17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18,
                  19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20,
                  20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21,
                  21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 22, 22,
                  22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22,
                  23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
                  23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
                  24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
                  24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25,
                  25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
                  25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26,
                  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
                  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
                  27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
                  27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
                  27, 27, 27, 28 );


{First normalized length for each code (0 = MIN_MATCH)}
  base_length: array[0..LENGTH_CODES-1] of int = (
                  0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28,
                  32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 0);


{First normalized distance for each code (0 = distance of 1)}
  base_dist: array[0..D_CODES-1] of int = (
                   0,    1,    2,    3,    4,    6,    8,    12,    16,    24,
                  32,   48,   64,   96,  128,  192,  256,   384,   512,   768,
                1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576 );




const
  MAX_BL_BITS = 7;   {Bit length codes must not exceed MAX_BL_BITS bits}
  END_BLOCK = 256;   {end of block literal code}
  REP_3_6 = 16;      {repeat previous bit length 3-6 times (2 bits of repeat count)}
  REPZ_3_10 = 17;    {repeat a zero length 3-10 times  (3 bits of repeat count)}
  REPZ_11_138 = 18;  {repeat a zero length 11-138 times  (7 bits of repeat count)}

const
  extra_lbits : array[0..LENGTH_CODES-1] of int = {extra bits for each length code}
                   (0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0);

const
  extra_dbits : array[0..D_CODES-1] of int = {extra bits for each distance code}
                   (0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13);

const
  extra_blbits: array[0..BL_CODES-1] of int = {extra bits for each bit length code}
                   (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,3,7);

const
  bl_order: array[0..BL_CODES-1] of uch =
              (16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15);
{The lengths of the bit length codes are sent in order of decreasing
  probability, to avoid transmitting the lengths for unused bit length codes.
}

const
  Buf_size = (8 * 2*sizeof(char8)); {Number of bits used within bi_buf. (bi_buf might be implemented on
                                    more than 16 bits on some systems.)}


const
  static_l_desc:  static_tree_desc  =
      (static_tree: @static_ltree;   {pointer to array of ct_data}
        extra_bits: @extra_lbits;    {pointer to array of int}
        extra_base: LITERALS+1;
             elems: L_CODES;
        max_length: MAX_BITS);

const
  static_d_desc: static_tree_desc  =
      (static_tree: @static_dtree;
        extra_bits: @extra_dbits;
        extra_base: 0;
             elems: D_CODES;
        max_length: MAX_BITS);

const
  static_bl_desc: static_tree_desc =
      (static_tree: nil;
        extra_bits: @extra_blbits;
        extra_base: 0;
             elems: BL_CODES;
        max_length: MAX_BL_BITS);




{---------------------------------------------------------------------------}
procedure send_bits(var  s: deflate_state;
                     value: int;   {value to send}
                    length: int); {number of bits}
  {-Send a value on a given number of bits.
    IN assertion: length <= 16 and value fits in length bits.}
begin
  {$ifdef DEBUG}
    Tracevv(' l '+IntToStr(length)+ ' v '+IntToStr(value));
    Assert((length > 0) and (length <= 15), 'invalid length');
    inc(s.bits_sent, ulg(length));
  {$endif}

  {If not enough room in bi_buf, use (valid) bits from bi_buf and
   (16 - bi_valid) bits from value, leaving (width - (16-bi_valid))
   unused bits in value.}

  {$ifopt Q+} {$Q-} {$define NoOverflowCheck} {$endif}
  {$ifopt R+} {$R-} {$define NoRangeCheck} {$endif}

  if s.bi_valid > int(Buf_size) - length then begin
    s.bi_buf := s.bi_buf or int(value shl s.bi_valid);
    {put_short(s, s.bi_buf);}
    s.pending_buf^[s.pending] := uch(s.bi_buf and $ff);
    inc(s.pending);
    s.pending_buf^[s.pending] := uch(ush(s.bi_buf) shr 8);;
    inc(s.pending);
    s.bi_buf := ush(value) shr (Buf_size - s.bi_valid);
    inc(s.bi_valid, length - Buf_size);
  end
  else begin
    s.bi_buf := s.bi_buf or int(value shl s.bi_valid);
    inc(s.bi_valid, length);
  end;
  {$ifdef NoOverflowCheck} {$Q+} {$undef NoOverflowCheck} {$endif}
  {$ifdef NoRangeCheck} {$Q+} {$undef NoRangeCheck} {$endif}
end;



{---------------------------------------------------------------------------}
function bi_reverse(code: unsigned; len: int): unsigned;
  {-Reverse the first len bits of a code}
  { using straightforward code (a faster method would use a table)
    IN assertion: 1 <= len <= 15}
var
  res: unsigned; {register}
begin
  res := 0;
  repeat
    res := res or (code and 1);
    code := code shr 1;
    res := res shl 1;
    dec(len);
  until len<=0;
  bi_reverse := res shr 1;
end;


{---------------------------------------------------------------------------}
procedure gen_codes(        tree: tree_ptr;       {the tree to decorate}
                        max_code: int;            {largest code with non zero frequency}
                    var bl_count: array of ushf); {number of codes at each bit length}

  {-Generate the codes for a given tree and bit counts (which need not be optimal).}
  { IN  assertion: the array bl_count contains the bit length statistics for
        the given tree and the field len is set for all tree elements.
    OUT assertion: the field code is set for all tree elements of non
        zero code length.}
var
  code: ush;    {running code value}
  bits: int;    {bit index}
  n: int;       {code index}
  len: int;
  next_code: array[0..MAX_BITS+1-1] of ush; {next code value for each bit length}

begin
  code := 0;

  {The distribution counts are first used to generate the code values
  without bit reversal.}

  for bits := 1 to MAX_BITS do begin
    code := (code + bl_count[bits-1]) shl 1;
    next_code[bits] := code;
  end;
  {Check that the bit counts in bl_count are consistent. The last code
   must be all ones.}

  {$ifdef DEBUG}
    Assert(code + bl_count[MAX_BITS]-1 = (1 shl MAX_BITS)-1, 'inconsistent bit counts');
    Tracev(#13#10'gen_codes: max_code '+IntToStr(max_code));
  {$endif}

  for n := 0 to max_code do begin
    len := tree^[n].dl.Len;
    if len=0 then continue;
    {Now reverse the bits}
    tree^[n].fc.Code := bi_reverse(next_code[len], len);
    inc(next_code[len]);
    {$ifdef DEBUG}
      if (n>31) and (n<128) then begin
        Tracecv(tree <> tree_ptr(@static_ltree),
         (#13#10'n #'+IntToStr(n)+' '+char8(n)+' l '+IntToStr(len)+' c '+
           IntToStr(tree^[n].fc.Code)+' ('+IntToStr(next_code[len]-1)+')'))
      end
      else begin
        Tracecv(tree <> tree_ptr(@static_ltree),
        (#13#10'n #'+IntToStr(n)+'   l '+IntToStr(len)+' c '+
           IntToStr(tree^[n].fc.Code)+' ('+IntToStr(next_code[len]-1)+')'));
      end;
    {$endif}
  end;
end;


{---------------------------------------------------------------------------}
procedure init_block(var s: deflate_state);
  {-Initialize a new block.}
var
  n: int; {iterates over tree elements}
begin
  {Initialize the trees.}
  for n := 0 to L_CODES-1  do s.dyn_ltree[n].fc.Freq := 0;
  for n := 0 to D_CODES-1  do s.dyn_dtree[n].fc.Freq := 0;
  for n := 0 to BL_CODES-1 do s.bl_tree[n].fc.Freq := 0;
  s.dyn_ltree[END_BLOCK].fc.Freq := 1;
  s.static_len := Long(0);
  s.opt_len := Long(0);
  s.matches := 0;
  s.last_lit := 0;
end;


{---------------------------------------------------------------------------}
procedure _tr_init(var s: deflate_state);
  {-Initialize the tree data structures for a new zlib stream.}
begin
  s.l_desc.dyn_tree := tree_ptr(@s.dyn_ltree);
  s.l_desc.stat_desc := @static_l_desc;

  s.d_desc.dyn_tree := tree_ptr(@s.dyn_dtree);
  s.d_desc.stat_desc := @static_d_desc;

  s.bl_desc.dyn_tree := tree_ptr(@s.bl_tree);
  s.bl_desc.stat_desc := @static_bl_desc;

  s.bi_buf := 0;
  s.bi_valid := 0;
  s.last_eob_len := 8; {enough lookahead for inflate}

  {$ifdef DEBUG}
    s.compressed_len := Long(0);   {*we 113}
    s.bits_sent := Long(0);
  {$endif}

  {Initialize the first block of the first file:}
  init_block(s);
end;



{---------------------------------------------------------------------------}
procedure pqdownheap(   var s: deflate_state;
                     var tree: tree_type;      {the tree to restore}
                            k: int);           {node to move down}
  {-Restore the heap property by moving down the tree starting at node k,
    exchanging a node with the smallest of its two sons if necessary, stopping
    when the heap property is re-established (each father smaller than its
    two sons).}
var
  v: int;
  j: int;
begin
  v := s.heap[k];
  j := k shl 1;  {left son of k}
  while j<=s.heap_len do begin
    {Set j to the smallest of the two sons:}
    if (j < s.heap_len) and
       {smaller(tree, s.heap[j+1], s.heap[j], s.depth)}
      ((tree[s.heap[j+1]].fc.Freq < tree[s.heap[j]].fc.Freq) or
        ((tree[s.heap[j+1]].fc.Freq = tree[s.heap[j]].fc.Freq) and
         (s.depth[s.heap[j+1]] <= s.depth[s.heap[j]]))) then
    begin
      inc(j);
    end;
    {Exit if v is smaller than both sons}
    if {(smaller(tree, v, s.heap[j], s.depth))}
     ((tree[v].fc.Freq < tree[s.heap[j]].fc.Freq) or
       ((tree[v].fc.Freq = tree[s.heap[j]].fc.Freq) and
        (s.depth[v] <= s.depth[s.heap[j]]))) then
    begin
      break;
    end;
    {Exchange v with the smallest son}
    s.heap[k] := s.heap[j];
    k := j;

    {And continue down the tree, setting j to the left son of k}
    j := j shl 1;
  end;
  s.heap[k] := v;
end;


{---------------------------------------------------------------------------}
procedure gen_bitlen(var s: deflate_state; var desc: tree_desc);
  {-Compute the optimal bit lengths for a tree and update the total bit length
    for the current block.
    IN assertion: the fields freq and dad are set, heap[heap_max] and
       above are the tree nodes sorted by increasing frequency.
    OUT assertions: the field len is set to the optimal bit length, the
        array bl_count contains the frequencies for each bit length.
        The length opt_len is updated; static_len is also updated if stree is
        not null.}
var
  tree: tree_ptr;
  max_code: int;
  stree: tree_ptr;     {const}
  extra: pzIntfArray;  {const}
  base: int;
  max_length: int;
  h: int;              {heap index}
  n, m: int;           {iterate over the tree elements}
  bits: int;           {bit length}
  xbits: int;          {extra bits}
  f: ush;              {frequency}
  overflow: int;       {number of elements with bit length too large}
begin
  tree := desc.dyn_tree;
  max_code := desc.max_code;
  stree := desc.stat_desc^.static_tree;
  extra := desc.stat_desc^.extra_bits;
  base := desc.stat_desc^.extra_base;
  max_length := desc.stat_desc^.max_length;
  overflow := 0;

  for bits := 0 to MAX_BITS do s.bl_count[bits] := 0;

  {In a first pass, compute the optimal bit lengths (which may
   overflow in the case of the bit length tree).}

  tree^[s.heap[s.heap_max]].dl.Len := 0; {root of the heap}

  for h := s.heap_max+1 to HEAP_SIZE-1 do begin
    n := s.heap[h];
    bits := tree^[tree^[n].dl.Dad].dl.Len + 1;
    if bits>max_length then begin
      bits := max_length;
      inc(overflow);
    end;
    tree^[n].dl.Len := ush(bits);
    {We overwrite tree[n].dl.Dad which is no longer needed}

    if n>max_code then continue; {not a leaf node}

    inc(s.bl_count[bits]);
    xbits := 0;
    if n>=base then xbits := extra^[n-base];
    f := tree^[n].fc.Freq;
    inc(s.opt_len, ulg(f) * (bits + xbits));
    if (stree <> nil) then
      inc(s.static_len, ulg(f) * (stree^[n].dl.Len + xbits));
  end;
  if overflow=0 then exit;

  {$ifdef DEBUG}
    Tracev(#13#10'bit length overflow');
  {$endif}
  {This happens for example on obj2 and pic of the Calgary corpus}

  {Find the first bit length which could increase:}
  repeat
    bits := max_length-1;
    while s.bl_count[bits]=0 do dec(bits);
    dec(s.bl_count[bits]);      {move one leaf down the tree}
    inc(s.bl_count[bits+1], 2); {move one overflow item as its brother}
    dec(s.bl_count[max_length]);
    {The brother of the overflow item also moves one step up,
     but this does not affect bl_count[max_length]}
    dec(overflow, 2);
  until overflow<=0;

  {Now recompute all bit lengths, scanning in increasing frequency.
   h is still equal to HEAP_SIZE. (It is simpler to reconstruct all
   lengths instead of fixing only the wrong ones. This idea is taken
   from 'ar' written by Haruhiko Okumura.)}

  h := HEAP_SIZE;  {Delphi3: compiler warning w/o this}
  for bits := max_length downto 1 do begin
    n := s.bl_count[bits];
    while n<>0 do begin
      dec(h);
      m := s.heap[h];
      if m>max_code then continue;
      if tree^[m].dl.Len <> unsigned(bits) then begin
        {$ifdef DEBUG}
          Trace('code '+IntToStr(m)+' bits '+IntToStr(tree^[m].dl.Len) +'.'+IntToStr(bits)+#13#10);
        {$endif}
        inc(s.opt_len, (long(bits) - long(tree^[m].dl.Len)) * long(tree^[m].fc.Freq));
        tree^[m].dl.Len := ush(bits);
      end;
      dec(n);
    end;
  end;
end;



{---------------------------------------------------------------------------}
procedure build_tree(var s: deflate_state; var desc: tree_desc);
  {-Construct one Huffman tree and assigns the code bit strings and lengths.
    Update the total bit length for the current block.
    IN assertion: the field freq is set for all tree elements.
    OUT assertions: the fields len and code are set to the optimal bit length
        and corresponding code. The length opt_len is updated; static_len is
        also updated if stree is not null. The field max_code is set.}

const
  SMALLEST = 1;  {Index within the heap array of least frequent node in the Huffman tree}
var
  tree: tree_ptr;
  stree: tree_ptr;    {const}
  elems: int;
  n, m: int;          {iterate over heap elements}
  max_code: int;      {largest code with non zero frequency}
  node: int;          {new node being created}
begin
  tree := desc.dyn_tree;
  stree := desc.stat_desc^.static_tree;
  elems := desc.stat_desc^.elems;
  max_code := -1;

  {Construct the initial heap, with least frequent element in
   heap[SMALLEST]. The sons of heap[n] are heap[2*n] and heap[2*n+1].
   heap[0] is not used.}

  s.heap_len := 0;
  s.heap_max := HEAP_SIZE;

  for n := 0 to elems-1 do begin
    if tree^[n].fc.Freq<>0 then begin
      max_code := n;
      inc(s.heap_len);
      s.heap[s.heap_len] := n;
      s.depth[n] := 0;
    end
    else tree^[n].dl.Len := 0;
  end;

  {The pkzip format requires that at least one distance code exists,
   and that at least one bit should be sent even if there is only one
   possible code. So to avoid special checks later on we force at least
   two codes of non zero frequency.}

  while s.heap_len<2 do begin
    inc(s.heap_len);
    if max_code<2 then begin
      inc(max_code);
      s.heap[s.heap_len] := max_code;
      node := max_code;
    end
    else begin
      s.heap[s.heap_len] := 0;
      node := 0;
    end;
    tree^[node].fc.Freq := 1;
    s.depth[node] := 0;
    dec(s.opt_len);
    if stree<>nil then dec(s.static_len, stree^[node].dl.Len);
    {node is 0 or 1 so it does not have extra bits}
  end;
  desc.max_code := max_code;

  {The elements heap[heap_len/2+1 .. heap_len] are leaves of the tree,
   establish sub-heaps of increasing lengths:}

  for n := s.heap_len div 2 downto 1 do pqdownheap(s, tree^, n);

  {Construct the Huffman tree by repeatedly combining the least two
   frequent nodes.}

  node := elems;              {next internal node of the tree}
  repeat
    {pqremove(s, tree, n);}  {n := node of least frequency}
    n := s.heap[SMALLEST];
    s.heap[SMALLEST] := s.heap[s.heap_len];
    dec(s.heap_len);
    pqdownheap(s, tree^, SMALLEST);
    m := s.heap[SMALLEST]; {m := node of next least frequency}
    dec(s.heap_max);
    s.heap[s.heap_max] := n; {keep the nodes sorted by frequency}
    dec(s.heap_max);
    s.heap[s.heap_max] := m;

    {Create a new node father of n and m}
    tree^[node].fc.Freq := tree^[n].fc.Freq + tree^[m].fc.Freq;
    {maximum}
    if s.depth[n] >= s.depth[m] then s.depth[node] := uch(s.depth[n] + 1)
    else s.depth[node] := uch(s.depth[m] + 1);

    tree^[m].dl.Dad := ush(node);
    tree^[n].dl.Dad := ush(node);
    {and insert the new node in the heap}
    s.heap[SMALLEST] := node;
    inc(node);
    pqdownheap(s, tree^, SMALLEST);
  until s.heap_len<2;

  dec(s.heap_max);
  s.heap[s.heap_max] := s.heap[SMALLEST];

  {At this point, the fields freq and dad are set. We can now
   generate the bit lengths.}

  gen_bitlen(s, desc);

  {The field len is now set, we can generate the bit codes}
  gen_codes (tree, max_code, s.bl_count);
end;



{---------------------------------------------------------------------------}
procedure scan_tree(   var s: deflate_state;
                    var tree: array of ct_data; {the tree to be scanned}
                    max_code: int);             {and its largest code of non zero frequency}
  {-Scan a literal or distance tree to determine the frequencies of the codes
    in the bit length tree.}
var
  n: int;                 {iterates over all tree elements}
  prevlen: int;           {last emitted length}
  curlen: int;            {length of current code}
  nextlen: int;           {length of next code}
  count: int;             {repeat count of the current code}
  max_count: int;         {max repeat count}
  min_count: int;         {min repeat count}
begin
  prevlen := -1;
  nextlen := tree[0].dl.Len;
  count := 0;
  max_count := 7;
  min_count := 4;

  if nextlen=0 then begin
    max_count := 138;
    min_count := 3;
  end;
  tree[max_code+1].dl.Len := ush($ffff); {guard}

  for n := 0 to max_code do begin
    curlen := nextlen;
    nextlen := tree[n+1].dl.Len;
    inc(count);
    if (count < max_count) and (curlen = nextlen) then continue
    else if count<min_count then inc(s.bl_tree[curlen].fc.Freq, count)
    else if curlen<>0 then begin
      if curlen<>prevlen then inc(s.bl_tree[curlen].fc.Freq);
      inc(s.bl_tree[REP_3_6].fc.Freq);
    end
    else if count<=10 then inc(s.bl_tree[REPZ_3_10].fc.Freq)
    else inc(s.bl_tree[REPZ_11_138].fc.Freq);

    count := 0;
    prevlen := curlen;
    if nextlen=0 then begin
      max_count := 138;
      min_count := 3;
    end
    else if curlen=nextlen then begin
      max_count := 6;
      min_count := 3;
    end
    else begin
      max_count := 7;
      min_count := 4;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure send_tree(   var s: deflate_state;
                    var tree: array of ct_data;  {the tree to be scanned}
                    max_code: int);              {and its largest code of non zero frequency}

  {-Send a literal or distance tree in compressed form, using the codes in bl_tree.}
var
  n: int;                {iterates over all tree elements}
  prevlen: int;          {last emitted length}
  curlen: int;           {length of current code}
  nextlen: int;          {length of next code}
  count: int;            {repeat count of the current code}
  max_count: int;        {max repeat count}
  min_count: int;        {min repeat count}
begin
  prevlen := -1;
  nextlen := tree[0].dl.Len;
  count := 0;
  max_count := 7;
  min_count := 4;

  {tree[max_code+1].dl.Len := -1;}  {guard already set}
  if nextlen=0 then begin
    max_count := 138;
    min_count := 3;
  end;

  for n := 0 to max_code do begin
    curlen := nextlen;
    nextlen := tree[n+1].dl.Len;
    inc(count);
    if (count < max_count) and (curlen = nextlen) then continue
    else if count<min_count then begin
      repeat
        {$ifdef DEBUG}
          Tracevvv(#13#10'cd '+IntToStr(curlen));
        {$endif}
        send_bits(s, s.bl_tree[curlen].fc.Code, s.bl_tree[curlen].dl.Len);
        dec(count);
      until (count = 0);
    end
    else if curlen<>0 then begin
      if curlen<>prevlen then begin
        {$ifdef DEBUG}
          Tracevvv(#13#10'cd '+IntToStr(curlen));
        {$endif}
        send_bits(s, s.bl_tree[curlen].fc.Code, s.bl_tree[curlen].dl.Len);
        dec(count);
      end;
      {$ifdef DEBUG}
        Assert((count >= 3) and (count <= 6), ' 3_6?');
        Tracevvv(#13#10'cd '+IntToStr(REP_3_6));
      {$endif}
      send_bits(s, s.bl_tree[REP_3_6].fc.Code, s.bl_tree[REP_3_6].dl.Len);
      send_bits(s, count-3, 2);
    end
    else if count<=10 then begin
      {$ifdef DEBUG}
        Tracevvv(#13#10'cd '+IntToStr(REPZ_3_10));
      {$endif}
      send_bits(s, s.bl_tree[REPZ_3_10].fc.Code, s.bl_tree[REPZ_3_10].dl.Len);
      send_bits(s, count-3, 3);
    end
    else begin
      {$ifdef DEBUG}
        Tracevvv(#13#10'cd '+IntToStr(REPZ_11_138));
      {$endif}
      send_bits(s, s.bl_tree[REPZ_11_138].fc.Code, s.bl_tree[REPZ_11_138].dl.Len);
      send_bits(s, count-11, 7);
    end;
    count := 0;
    prevlen := curlen;
    if nextlen=0 then begin
      max_count := 138;
      min_count := 3;
    end
    else if curlen=nextlen then begin
      max_count := 6;
      min_count := 3;
    end
    else begin
      max_count := 7;
      min_count := 4;
    end;
  end;
end;


{---------------------------------------------------------------------------}
function build_bl_tree(var s: deflate_state): int;
  {-Construct the Huffman tree for the bit lengths and return the index in
    bl_order of the last bit length code to send.}
var
  max_blindex: int;  {index of last bit length code of non zero freq}
begin
  {Determine the bit length frequencies for literal and distance trees}
  scan_tree(s, s.dyn_ltree, s.l_desc.max_code);
  scan_tree(s, s.dyn_dtree, s.d_desc.max_code);

  {Build the bit length tree:}
  build_tree(s, s.bl_desc);
  {opt_len now includes the length of the tree representations, except
    the lengths of the bit lengths codes and the 5+5+4 bits for the counts.}

  {Determine the number of bit length codes to send. The pkzip format
    requires that at least 4 bit length codes be sent. (appnote.txt says
    3 but the actual value used is 4.)}

  for max_blindex := BL_CODES-1 downto 3 do begin
    if s.bl_tree[bl_order[max_blindex]].dl.Len <> 0 then break;
  end;
  {Update opt_len to include the bit length tree and counts}
  inc(s.opt_len, 3*(max_blindex+1) + 5+5+4);
  {$ifdef DEBUG}
    Tracev(#13#10'dyn trees: dyn '+IntToStr(s.opt_len)+', stat '+IntToStr(s.static_len));
  {$endif}

  build_bl_tree := max_blindex;
end;


{---------------------------------------------------------------------------}
procedure send_all_trees(var s: deflate_state; lcodes, dcodes, blcodes: int);
  {-Send the header for a block using dynamic Huffman trees: the counts, the
    lengths of the bit length codes, the literal tree and the distance tree.
    IN assertion: lcodes >= 257, dcodes >= 1, blcodes >= 4.}
var
  rank: int; {index in bl_order}
begin
  {$ifdef DEBUG}
    Assert((lcodes >= 257) and (dcodes >= 1) and (blcodes >= 4), 'not enough codes');
    Assert((lcodes <= L_CODES) and (dcodes <= D_CODES) and (blcodes <= BL_CODES), 'too many codes');
    Tracev(#13#10'bl counts: ');
  {$endif}

  send_bits(s, lcodes-257, 5); {not +255 as stated in appnote.txt}
  send_bits(s, dcodes-1,   5);
  send_bits(s, blcodes-4,  4); {not -3 as stated in appnote.txt}

  for rank := 0 to blcodes-1 do begin
    {$ifdef DEBUG}
      Tracev(#13#10'bl code '+IntToStr(bl_order[rank]));
    {$endif}
    send_bits(s, s.bl_tree[bl_order[rank]].dl.Len, 3);
  end;
  {$ifdef DEBUG}
    Tracev(#13#10'bl tree: sent '+IntToStr(s.bits_sent));
  {$endif}

  send_tree(s, s.dyn_ltree, lcodes-1); {literal tree}
  {$ifdef DEBUG}
    Tracev(#13#10'lit tree: sent '+IntToStr(s.bits_sent));
  {$endif}

  send_tree(s, s.dyn_dtree, dcodes-1); {distance tree}
  {$ifdef DEBUG}
    Tracev(#13#10'dist tree: sent '+IntToStr(s.bits_sent));
  {$endif}
end;


{---------------------------------------------------------------------------}
procedure bi_windup(var s: deflate_state);
  {-Flush the bit buffer and align the output on a byte boundary}
begin
  if s.bi_valid>8 then begin
    {put_short(s, s.bi_buf);}
    s.pending_buf^[s.pending] := uch(s.bi_buf and $ff);
    inc(s.pending);
    s.pending_buf^[s.pending] := uch(ush(s.bi_buf) shr 8);;
    inc(s.pending);
  end
  else if s.bi_valid>0 then begin
    {put_byte(s, (byte)s^.bi_buf);}
    s.pending_buf^[s.pending] := byte(s.bi_buf);
    inc(s.pending);
  end;
  s.bi_buf := 0;
  s.bi_valid := 0;
  {$ifdef DEBUG}
    s.bits_sent := (s.bits_sent+7) and (not 7);
  {$endif}
end;



{---------------------------------------------------------------------------}
procedure copy_block( var s: deflate_state;
                        buf: pcharf;        {the input data}
                        len: unsigned;      {its length}
                     header: boolean);      {true if block header must be written}
  {-Copy a stored block, storing first the length and its one's complement if requested.}
begin
  bi_windup(s);        {align on byte boundary}
  s.last_eob_len := 8; {enough lookahead for inflate}

  if header then begin
    {put_short(s, (ush)len);}
    s.pending_buf^[s.pending] := uch(ush(len) and $ff);
    inc(s.pending);
    s.pending_buf^[s.pending] := uch(ush(len) shr 8);;
    inc(s.pending);
    {put_short(s, (ush)~len);}
    s.pending_buf^[s.pending] := uch(ush(not len) and $ff);
    inc(s.pending);
    s.pending_buf^[s.pending] := uch(ush(not len) shr 8);;
    inc(s.pending);
    {$ifdef DEBUG}
      inc(s.bits_sent, 2*16);
    {$endif}
  end;
  {$ifdef DEBUG}
    {*we 2006-12-09, fixed old paszlib bug: ulg(len) shl 3}
    {replaces buggy expression ulg(len shl 3)}
    inc(s.bits_sent, ulg(len) shl 3);
  {$endif}
  while len<>0 do begin
    dec(len);
    {put_byte(s, *buf++);}
    s.pending_buf^[s.pending] := buf^;
    inc(buf);
    inc(s.pending);
  end;
end;



{---------------------------------------------------------------------------}
procedure _tr_stored_block(     var s: deflate_state;
                                  buf: pcharf;       {input block}
                           stored_len: ulg;          {length of input block}
                                  eof: boolean);     {true if this is the last block for a file}
  {-Send a stored block}
begin
  send_bits(s, (STORED_BLOCK shl 1)+ord(eof), 3);  {send block type}
  {$ifdef DEBUG} {*we 113}
    s.compressed_len := (s.compressed_len + 3 + 7) and ulg(not Long(7));
    inc(s.compressed_len, (stored_len + 4) shl 3);
  {$endif}
  copy_block(s, buf, unsigned(stored_len), true); {with header}
end;


{---------------------------------------------------------------------------}
procedure bi_flush(var s: deflate_state);
  {-Flush the bit buffer, keeping at most 7 bits in it.}
begin
  if s.bi_valid=16 then begin
    {put_short(s, s.bi_buf);}
    s.pending_buf^[s.pending] := uch(s.bi_buf and $ff);
    inc(s.pending);
    s.pending_buf^[s.pending] := uch(ush(s.bi_buf) shr 8);;
    inc(s.pending);
    s.bi_buf := 0;
    s.bi_valid := 0;
  end
  else if s.bi_valid >= 8 then begin
    {put_byte(s, (byte)s^.bi_buf);}
    s.pending_buf^[s.pending] := byte(s.bi_buf);
    inc(s.pending);
    s.bi_buf := s.bi_buf shr 8;
    dec(s.bi_valid, 8);
  end;
end;



{---------------------------------------------------------------------------}
procedure _tr_align(var s: deflate_state);
  {-Send one empty static block to give enough lookahead for inflate.}

  {This takes 10 bits, of which 7 may remain in the bit buffer.
  The current inflate code requires 9 bits of lookahead. If the
  last two codes for the previous block (real code plus EOB) were coded
  on 5 bits or less, inflate may have only 5+3 bits of lookahead to decode
  the last real code. In this case we send two empty static blocks instead
  of one. (There are no problems if the previous block is stored or fixed.)
  To simplify the code, we assume the worst case of last real code encoded
  on one bit only.}
begin
  send_bits(s, STATIC_TREES shl 1, 3);
  {$ifdef DEBUG}
    Tracevvv(#13#10'cd '+IntToStr(END_BLOCK));
  {$endif}
  send_bits(s, static_ltree[END_BLOCK].fc.Code, static_ltree[END_BLOCK].dl.Len);
  {$ifdef DEBUG} {*we 113}
    inc(s.compressed_len, Long(10)); {3 for block type, 7 for EOB}
  {$endif}
  bi_flush(s);
  {Of the 10 bits for the empty block, we have already sent
   (10 - bi_valid) bits. The lookahead for the last real code (before
   the EOB of the previous block) was thus at least one plus the length
   of the EOB plus what we have just sent of the empty static block.}

  if 1 + s.last_eob_len + 10 - s.bi_valid < 9 then begin
    send_bits(s, STATIC_TREES shl 1, 3);
    {$ifdef DEBUG}
      Tracevvv(#13#10'cd '+IntToStr(END_BLOCK));
    {$endif}
    send_bits(s, static_ltree[END_BLOCK].fc.Code, static_ltree[END_BLOCK].dl.Len);
    {$ifdef DEBUG} {*we 113}
      inc(s.compressed_len, Long(10));
    {$endif}
    bi_flush(s);
  end;
  s.last_eob_len := 7;
end;



{---------------------------------------------------------------------------}
procedure set_data_type(var s: deflate_state);
  {-Set the data type to ASCII or BINARY, using a crude approximation:
    binary if more than 20% of the bytes are <= 6 or >= 128, ascii otherwise.
    IN assertion: the fields freq of dyn_ltree are set and the total of all
    frequencies does not exceed 64K (to fit in an int on 16 bit machines).}
var
  n: int;
  ascii_freq: unsigned;
  bin_freq: unsigned;
begin
  n := 0;
  ascii_freq := 0;
  bin_freq := 0;

  while n<7 do begin
    inc(bin_freq, s.dyn_ltree[n].fc.Freq);
    inc(n);
  end;

  while n<128 do begin
    inc(ascii_freq, s.dyn_ltree[n].fc.Freq);
    inc(n);
  end;

  while n<LITERALS do begin
    inc(bin_freq, s.dyn_ltree[n].fc.Freq);
    inc(n);
  end;

  if bin_freq>(ascii_freq shr 2) then s.data_type := byte(Z_BINARY)
  else s.data_type := byte(Z_ASCII);
end;


{---------------------------------------------------------------------------}
procedure compress_block(      var s: deflate_state;
                         const ltree: array of ct_data;   {literal tree}  {*we var -> const}
                         const dtree: array of ct_data);  {distance tree} {*we var -> const}
  {-Send the block data compressed using the given Huffman trees}
var
  dist: unsigned;      {distance of matched string}
  lc: int;             {match length or unmatched char (if dist == 0)}
  lx: unsigned;        {running index in l_buf}
  code: unsigned;      {the code to send}
  extra: int;          {number of extra bits to send}
begin
  lx := 0;
  if s.last_lit<>0 then repeat
    dist := s.d_buf^[lx];
    lc := s.l_buf^[lx];
    inc(lx);
    if dist=0 then begin
      {send a literal byte}
      {$ifdef DEBUG}
        Tracevvv(#13#10'cd '+IntToStr(lc));
        Tracecv((lc > 31) and (lc < 128),{$ifdef unicode}str255{$endif} (' '+char8(lc)+' '#13#10));
      {$endif}
      send_bits(s, ltree[lc].fc.Code, ltree[lc].dl.Len);
    end
    else begin
      {Here, lc is the match length - MIN_MATCH}
      code := _length_code[lc];
      {send the length code}
      {$ifdef DEBUG}
        Tracevvv(#13#10'cd '+IntToStr(code+LITERALS+1));
      {$endif}
      send_bits(s, ltree[code+LITERALS+1].fc.Code, ltree[code+LITERALS+1].dl.Len);
      extra := extra_lbits[code];
      if extra<>0 then begin
        dec(lc, base_length[code]);
        send_bits(s, lc, extra);       {send the extra length bits}
      end;
      dec(dist); {dist is now the match distance - 1}
      {code := d_code(dist);}
      if dist<256 then code := _dist_code[dist]
      else code := _dist_code[256+(dist shr 7)];

      {$ifdef DEBUG}
        Assert (code < D_CODES, 'bad d_code');
        Tracevvv(#13#10'cd '+IntToStr(code));
      {$endif}

      {send the distance code}
      send_bits(s, dtree[code].fc.Code, dtree[code].dl.Len);
      extra := extra_dbits[code];
      if extra<>0 then begin
        dec(dist, base_dist[code]);
        send_bits(s, dist, extra);   {send the extra distance bits}
      end;
    end; {literal or match pair ?}

    {Check that the overlay between pending_buf and d_buf+l_buf is ok:}
    {$ifdef DEBUG}
      Assert(s.pending < Long(s.lit_bufsize + 2*lx), 'pendingBuf overflow');
    {$endif}
  until lx >= s.last_lit;

  {$ifdef DEBUG}
    Tracevvv(#13#10'cd '+IntToStr(END_BLOCK));
  {$endif}
  send_bits(s, ltree[END_BLOCK].fc.Code, ltree[END_BLOCK].dl.Len);
  s.last_eob_len := ltree[END_BLOCK].dl.Len;
end;



{---------------------------------------------------------------------------}
procedure _tr_flush_block(    var s: deflate_state; {*we 113}
                                buf: pcharf;        {input block, or NULL if too old}
                         stored_len: ulg;           {length of input block}
                                eof: boolean);      {true if this is the last block for a file}
  {-Determine the best encoding for the current block: dynamic trees, static
    trees or store, and output the encoded block to the zip file.} {*we 113}
var
  opt_lenb, static_lenb: ulg; {opt_len and static_len in bytes}
  max_blindex: int;  {index of last bit length code of non zero freq}
begin
  max_blindex := 0;

  {Build the Huffman trees unless a stored block is forced}
  if s.level>0 then begin
    {Check if the file is ascii or binary}
    if s.data_type=Z_UNKNOWN then set_data_type(s);

    {Construct the literal and distance trees}
    build_tree(s, s.l_desc);
    {$ifdef DEBUG}
      Tracev(#13#10'lit data: dyn '+IntToStr(s.opt_len)+', stat '+IntToStr(s.static_len));
    {$endif}

    build_tree(s, s.d_desc);
    {$ifdef DEBUG}
      Tracev(#13#10'dist data: dyn '+IntToStr(s.opt_len)+', stat '+IntToStr(s.static_len));
    {$endif}
    {At this point, opt_len and static_len are the total bit lengths of
     the compressed block data, excluding the tree representations.}

    {Build the bit length tree for the above two trees, and get the index
     in bl_order of the last bit length code to send.}
    max_blindex := build_bl_tree(s);

    {Determine the best encoding. Compute first the block length in bytes}
    opt_lenb := (s.opt_len+3+7) shr 3;
    static_lenb := (s.static_len+3+7) shr 3;

    {$ifdef DEBUG}
      Tracev(#13#10'opt '   +IntToStr(opt_lenb)+'('+IntToStr(s.opt_len)+') '+
                   'stat '  +IntToStr(static_lenb)+'('+IntToStr(s.static_len)+') '+
                   'stored '+IntToStr(stored_len)+' lit '+IntToStr(s.last_lit));
    {$endif}

    if static_lenb<=opt_lenb then opt_lenb := static_lenb;

  end
  else begin
    {$ifdef DEBUG}
      Assert(buf <> pcharf(nil), 'lost buf');
    {$endif}
    static_lenb := stored_len + 5;
    opt_lenb := static_lenb;        {force a stored block}
  end;

  {*we 113: Parts deleted}

  if (stored_len+4 <= opt_lenb) and (buf<>pcharf(Z_NULL)) then begin  {*we 0202: 0 -> Z_NULL}
    _tr_stored_block(s, buf, stored_len, eof);
  end
  else if static_lenb=opt_lenb then begin
    send_bits(s, (STATIC_TREES shl 1)+ord(eof), 3);
    compress_block(s, static_ltree, static_dtree);
    {$ifdef DEBUG} {*we 113}
      inc(s.compressed_len, 3 + s.static_len);
    {$endif}
  end
  else begin
    send_bits(s, (DYN_TREES shl 1)+ord(eof), 3);
    send_all_trees(s, s.l_desc.max_code+1, s.d_desc.max_code+1, max_blindex+1);
    compress_block(s, s.dyn_ltree, s.dyn_dtree);
    {$ifdef DEBUG} {*we 113}
      inc(s.compressed_len, 3 + s.opt_len);
    {$endif}
  end;

  {$ifdef DEBUG}
    Assert (s.compressed_len = s.bits_sent, 'bad compressed size');
    (*
    if s.compressed_len <> s.bits_sent then
      Tracev(#13#10'Bad compressed size: compressed_len='+IntToStr(s.compressed_len)
              +',   bits_sent'+IntToStr(s.bits_sent));
    *)
  {$else}

  {$endif}
  init_block(s);

  if eof then begin
    bi_windup(s);
    {$ifdef DEBUG} {*we 113}
      inc(s.compressed_len, 7);  {align on byte boundary}
    {$endif}
  end;
  {$ifdef DEBUG}
    Tracev(#13#10'comprlen '+IntToStr(s.compressed_len shr 3)+'('+IntToStr(s.compressed_len-7*ord(eof))+')');
  {$endif}

  { _tr_flush_block := s.compressed_len shr 3;} {*we 113}
end;



{---------------------------------------------------------------------------}
function _tr_tally(var s: deflate_state; dist: unsigned; lc: unsigned): boolean;
  {-Save the match info and tally the frequency counts. Return true if
    the current block must be flushed, dist:  distance of matched string}
var
  code: ush;
  {$ifdef TRUNCATE_BLOCK}
    out_length: ulg;
    in_length: ulg;
    dcode: int;
  {$endif}
begin
  s.d_buf^[s.last_lit] := ush(dist);
  s.l_buf^[s.last_lit] := uch(lc);
  inc(s.last_lit);
  if dist=0 then begin
    {lc is the unmatched char}
    inc(s.dyn_ltree[lc].fc.Freq);
  end
  else begin
    inc(s.matches);
    {Here, lc is the match length - MIN_MATCH}
    dec(dist);             {dist := match distance - 1}

    {macro d_code(dist)}
    if dist<256 then code := _dist_code[dist]
    else code := _dist_code[256+(dist shr 7)];
    {$ifdef DEBUG}
      {macro  MAX_DIST(s) <=> ((s)^.w_size-MIN_LOOKAHEAD)
      In order to simplify the code, particularly on 16 bit machines, match
      distances are limited to MAX_DIST instead of WSIZE.}
      Assert((dist < ush(s.w_size-(MAX_MATCH+MIN_MATCH+1))) and
              (ush(lc) <= ush(MAX_MATCH-MIN_MATCH)) and
              (ush(code) < ush(D_CODES)),  '_tr_tally: bad match');
    {$endif}
    inc(s.dyn_ltree[_length_code[lc]+LITERALS+1].fc.Freq);
    {s.dyn_dtree[d_code(dist)].Freq++;}
    inc(s.dyn_dtree[code].fc.Freq);
  end;

  {$ifdef TRUNCATE_BLOCK}
    {Try to guess if it is profitable to stop the current block here}
    if (s.last_lit and $1fff = 0) and (s.level > 2) then begin
      {Compute an upper bound for the compressed length}
      out_length := ulg(s.last_lit)*Long(8);
      in_length := ulg(long(s.strstart) - s.block_start);
      for dcode := 0 to D_CODES-1 do begin
        inc(out_length, ulg(s.dyn_dtree[dcode].fc.Freq * (Long(5)+extra_dbits[dcode])));
      end;
      out_length := out_length shr 3;
      {$ifdef DEBUG}
        Tracev(#13#10'last_lit '+IntToStr(s.last_lit)+', in '+IntToStr(in_length)+
               ', out ~'+IntToStr(out_length)+'('+IntToStr(100 - long(100)*out_length div in_length)+'%)');
      {$endif}
      if (s.matches<s.last_lit div 2) and (out_length<in_length div 2) then begin
        _tr_tally := true;
        exit;
      end;
    end;
  {$endif}

  _tr_tally := (s.last_lit = s.lit_bufsize-1);

  {We avoid equality with lit_bufsize because of wraparound at 64K on
  16 bit machines and because stored blocks are restricted to 64K-1 bytes.}
end;

end.
