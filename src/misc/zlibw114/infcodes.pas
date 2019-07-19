unit InfCodes;

(************************************************************************
  infcodes.c -- process literals and length/distance pairs
  Copyright (C) 1995-2002 Mark Adler

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Aug 2000
    - ZLIB 113 changes
  Feb 2002
    - Source code reformating/reordering
  Mar 2002
    - ZLIB 114 changes,
    - Patches by Mark Adler (pers. comm.)
  Mar 2005
    - Code cleanup for WWW upload
  May 2005
    - Trace: use #13#10 like C original
  Jul 2009
    - D12 fixes
  ------------------------------------------------------------------------

*************************************************************************)

interface

uses
  zlibh, infutil;

function inflate_codes_new(bl, bd: uInt; tl, td: pInflate_huft; var z: z_stream): pInflate_codes_state;

function inflate_codes(var s: inflate_blocks_state; var z: z_stream;r: int): int;

procedure inflate_codes_free(c: pInflate_codes_state; var z: z_stream);


implementation

{$I zconf.inc}

uses
  zutil, inffast;

{---------------------------------------------------------------------------}
function inflate_codes_new(bl, bd: uInt; tl, td: pInflate_huft; var z: z_stream): pInflate_codes_state;
var
  c: pInflate_codes_state;
begin
  c := pInflate_codes_state(Z_ALLOC(z,1,sizeof(inflate_codes_state)));
  if c<>Z_NULL then with c^ do begin
    mode := _START;
    lbits := byte(bl);
    dbits := byte(bd);
    ltree := tl;
    dtree := td;
    {$ifdef DEBUG}
      Tracev('inflate:       codes new'#13#10);
    {$endif}
  end;
  inflate_codes_new := c;
end;


{---------------------------------------------------------------------------}
function inflate_codes(var s: inflate_blocks_state; var z: z_stream; r: int): int;
var
  j: uInt;               {temporary storage}
  t: pInflate_huft;      {temporary pointer}
  e: uInt;               {extra bits or operation}
  b: uLong;              {bit buffer}
  k: uInt;               {bits in bit buffer}
  p: pBytef;             {input data pointer}
  n: uInt;               {bytes available there}
  q: pBytef;             {output window write pointer}
  m: uInt;               {bytes to end of window or read pointer}
  f: pBytef;             {pointer to copy strings from}
var
  c: pInflate_codes_state;

begin
  c := s.sub.decode.codes;  {codes state}

  {copy input/output information to locals}
  p := z.next_in;
  n := z.avail_in;
  b := s.bitb;
  k := s.bitk;
  q := s.write;
  if ptr2int(q) < ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
  else m := uInt(ptr2int(s.zend)-ptr2int(q));

  {process input and output based on current state}
  while true do begin

    case c^.mode of
      {waiting for "i:"=input, "o:"=output, "x:"=nothing}

   _START: begin
             {x: set up for LEN}
             {$ifndef SLOW}
               if (m >= 258) and (n >= 10) then begin
                 {UPDATE}
                 s.bitb := b;
                 s.bitk := k;
                 z.avail_in := n;
                 inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                 z.next_in := p;
                 s.write := q;

                 r := inflate_fast(c^.lbits, c^.dbits, c^.ltree, c^.dtree, s, z);
                 {LOAD}
                 p := z.next_in;
                 n := z.avail_in;
                 b := s.bitb;
                 k := s.bitk;
                 q := s.write;
                 if ptr2int(q) < ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                 else m := uInt(ptr2int(s.zend)-ptr2int(q));

                 if r<>Z_OK then begin
                   if r=Z_STREAM_END then c^.mode := _WASH else c^.mode := _BADCODE;
                   continue;    {break for switch-statement in C}
                 end;
               end;
             {$endif} {not SLOW}
             c^.sub.code.need := c^.lbits;
             c^.sub.code.tree := c^.ltree;
             c^.mode := _LEN;  {falltrough}
           end;
    _LEN:  begin
             {i: get length/literal/eob next}
             j := c^.sub.code.need;
             {NEEDBITS(j);}
             while k<j do begin
               {NEEDBYTE;}
               if n<>0 then r :=Z_OK
               else begin
                 {UPDATE}
                 s.bitb := b;
                 s.bitk := k;
                 z.avail_in := n;
                 inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                 z.next_in := p;
                 s.write := q;
                 inflate_codes := inflate_flush(s,z,r);
                 exit;
               end;
               dec(n);
               b := b or (uLong(p^) shl k);
               inc(p);
               inc(k, 8);
             end;
             t := c^.sub.code.tree;
             inc(t, uInt(b) and inflate_mask[j]);
             {DUMPBITS(t^.bits);}
             b := b shr t^.bits;
             dec(k, t^.bits);

             e := uInt(t^.exop);
             if e=0 then begin
               {literal}
               c^.sub.lit := t^.base;
               {$ifdef DEBUG}
                 if (t^.base >= $20) and (t^.base < $7f) then
                   Tracevv({$ifdef unicode}str255{$endif}('inflate:         literal '+char8(t^.base)+#13#10))
                 else
                   Tracevv('inflate:         literal '+IntToStr(t^.base)+#13#10);
               {$endif}
               c^.mode := _LIT;
               continue;  {break switch statement}
             end;
             if e and 16 <> 0 then begin
               {length}
               c^.sub.copy.get := e and 15;
               c^.len := t^.base;
               c^.mode := _LENEXT;
               continue;         {break C-switch statement}
             end;
             if e and 64 = 0 then begin
               {next table}
               c^.sub.code.need := e;
               c^.sub.code.tree := @huft_ptr(t)^[t^.base];
               continue;         {break C-switch statement}
             end;
             if e and 32 <> 0 then begin
               {end of block}
               {$ifdef DEBUG}
                 Tracevv('inflate:         end of block'#13#10);
               {$endif}
               c^.mode := _WASH;
               continue;         {break C-switch statement}
             end;
             c^.mode := _BADCODE;        {invalid code}
             z.msg := 'invalid literal/length code';
             r := Z_DATA_ERROR;
             {UPDATE}
             s.bitb := b;
             s.bitk := k;
             z.avail_in := n;
             inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
             z.next_in := p;
             s.write := q;
             inflate_codes := inflate_flush(s,z,r);
             exit;
           end;

  _LENEXT: begin
             {i: getting length extra (have base)}
             j := c^.sub.copy.get;
             {NEEDBITS(j);}
             while k<j do begin
               {NEEDBYTE;}
               if n<>0 then r :=Z_OK
               else begin
                 {UPDATE}
                 s.bitb := b;
                 s.bitk := k;
                 z.avail_in := n;
                 inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                 z.next_in := p;
                 s.write := q;
                 inflate_codes := inflate_flush(s,z,r);
                 exit;
               end;
               dec(n);
               b := b or (uLong(p^) shl k);
               inc(p);
               inc(k, 8);
             end;
             inc(c^.len, uInt(b and inflate_mask[j]));
             {DUMPBITS(j);}
             b := b shr j;
             dec(k, j);

             c^.sub.code.need := c^.dbits;
             c^.sub.code.tree := c^.dtree;
             {$ifdef DEBUG}
               Tracevv('inflate:         length '+IntToStr(c^.len)+#13#10);
             {$endif}
             c^.mode := _DIST;
             {falltrough}
           end;

    _DIST: begin
             {i: get distance next}
             j := c^.sub.code.need;
             {NEEDBITS(j);}
             while k<j do begin
               {NEEDBYTE;}
               if n<>0 then r :=Z_OK
               else begin
                 {UPDATE}
                 s.bitb := b;
                 s.bitk := k;
                 z.avail_in := n;
                 inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                 z.next_in := p;
                 s.write := q;
                 inflate_codes := inflate_flush(s,z,r);
                 exit;
               end;
               dec(n);
               b := b or (uLong(p^) shl k);
               inc(p);
               inc(k, 8);
             end;
             t := @huft_ptr(c^.sub.code.tree)^[uInt(b) and inflate_mask[j]];
             {DUMPBITS(t^.bits);}
             b := b shr t^.bits;
             dec(k, t^.bits);

             e := uInt(t^.exop);
             if e and 16 <> 0 then begin
               {distance}
               c^.sub.copy.get := e and 15;
               c^.sub.copy.dist := t^.base;
               c^.mode := _DISTEXT;
               continue;     {break C-switch statement}
             end;
             if e and 64 = 0 then begin
               {next table}
               c^.sub.code.need := e;
               c^.sub.code.tree := @huft_ptr(t)^[t^.base];
               continue;     {break C-switch statement}
             end;
             c^.mode := _BADCODE;        {invalid code}
             z.msg := 'invalid distance code';
             r := Z_DATA_ERROR;
             {UPDATE}
             s.bitb := b;
             s.bitk := k;
             z.avail_in := n;
             inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
             z.next_in := p;
             s.write := q;
             inflate_codes := inflate_flush(s,z,r);
             exit;
           end;

 _DISTEXT: begin
             {i: getting distance extra}
             j := c^.sub.copy.get;
             {NEEDBITS(j);}
             while k<j do begin
               {NEEDBYTE;}
               if n<>0 then r :=Z_OK
               else begin
                 {UPDATE}
                 s.bitb := b;
                 s.bitk := k;
                 z.avail_in := n;
                 inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                 z.next_in := p;
                 s.write := q;
                 inflate_codes := inflate_flush(s,z,r);
                 exit;
               end;
               dec(n);
               b := b or (uLong(p^) shl k);
               inc(p);
               inc(k, 8);
             end;
             inc(c^.sub.copy.dist, uInt(b) and inflate_mask[j]);
             {DUMPBITS(j);}
             b := b shr j;
             dec(k, j);
             {$ifdef DEBUG}
               Tracevv('inflate:         distance '+ IntToStr(c^.sub.copy.dist)+#13#10);
             {$endif}
             c^.mode := _COPY;
             {falltrough}
           end;

    _COPY: begin
             {o: copying bytes in window, waiting for space}
             {*we 114}
             f := q;
             dec(f, c^.sub.copy.dist);
             {*we: 114MA - Mark Adler Patch}
             while (ptr2int(f) < ptr2int(s.window)) or (ptr2int(f) >= ptr2int(s.zend)) do begin
               {modulo window size-"while" instead of "if" handles invalid distances}
               inc(f, ptr2int(s.zend)-ptr2int(s.window));
             end;

             while c^.len<>0 do begin
               {NEEDOUT}
               if m=0 then begin
                 {WRAP}
                 if (q=s.zend) and (s.read <> s.window) then begin
                   q := s.window;
                   if ptr2int(q) < ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                   else m := uInt(ptr2int(s.zend)-ptr2int(q));
                 end;

                 if m=0 then begin
                   {FLUSH}
                   s.write := q;
                   r := inflate_flush(s,z,r);
                   q := s.write;
                   if ptr2int(q) < ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                   else m := uInt(ptr2int(s.zend)-ptr2int(q));

                   {WRAP}
                   if (q = s.zend) and (s.read <> s.window) then begin
                     q := s.window;
                     if ptr2int(q) < ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                     else m := uInt(ptr2int(s.zend)-ptr2int(q));
                   end;

                   if m=0 then begin
                     {UPDATE}
                     s.bitb := b;
                     s.bitk := k;
                     z.avail_in := n;
                     inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                     z.next_in := p;
                     s.write := q;
                     inflate_codes := inflate_flush(s,z,r);
                     exit;
                   end;
                 end;
               end;
               r := Z_OK;

               {OUTBYTE(*f++)}
               q^ := f^;
               inc(q);
               inc(f);
               dec(m);

               if f=s.zend then f := s.window;
               dec(c^.len);
             end;
             c^.mode := _START;
             {C-switch break; not needed}
           end;

    _LIT:  begin
             {o: got literal, waiting for output space}
             {NEEDOUT}
             if m=0 then begin
               {WRAP}
               if (q=s.zend) and (s.read<>s.window) then begin
                 q := s.window;
                 if ptr2int(q) < ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                 else m := uInt(ptr2int(s.zend)-ptr2int(q));
               end;

               if m=0 then begin
                 {FLUSH}
                 s.write := q;
                 r := inflate_flush(s,z,r);
                 q := s.write;
                 if ptr2int(q) < ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                 else m := uInt(ptr2int(s.zend)-ptr2int(q));

                 {WRAP}
                 if (q=s.zend) and (s.read<>s.window) then begin
                   q := s.window;
                   if ptr2int(q)<ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                   else m := uInt(ptr2int(s.zend)-ptr2int(q));
                 end;

                 if m=0 then begin
                   {UPDATE}
                   s.bitb := b;
                   s.bitk := k;
                   z.avail_in := n;
                   inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                   z.next_in := p;
                   s.write := q;
                   inflate_codes := inflate_flush(s,z,r);
                   exit;
                 end;
               end;
             end;
             r := Z_OK;

             {OUTBYTE(c^.sub.lit);}
             q^ := c^.sub.lit;
             inc(q);
             dec(m);

             c^.mode := _START;
             {break;}
           end;

    _WASH: begin
             {o: got eob, possibly more output}
             {*we 113, patch112 code}
             if k>7 then begin
               {return unused byte, if any}
               {$ifdef DEBUG}
                 Assert(k < 16, 'inflate_codes grabbed too many bytes');
               {$endif}
               dec(k, 8);
               inc(n);
               dec(p);                    {can always return one}
             end;
             {FLUSH}
             s.write := q;
             r := inflate_flush(s,z,r);
             q := s.write;
             if ptr2int(q)<ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
             else m := uInt(ptr2int(s.zend)-ptr2int(q));

             if s.read<>s.write then begin
               {UPDATE}
               s.bitb := b;
               s.bitk := k;
               z.avail_in := n;
               inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
               z.next_in := p;
               s.write := q;
               inflate_codes := inflate_flush(s,z,r);
               exit;
             end;
             c^.mode := _ZEND;
             {falltrough}
           end;

    _ZEND: begin
             r := Z_STREAM_END;
             {UPDATE}
             s.bitb := b;
             s.bitk := k;
             z.avail_in := n;
             inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
             z.next_in := p;
             s.write := q;
             inflate_codes := inflate_flush(s,z,r);
             exit;
           end;
 _BADCODE: begin
             {x: got error}
             r := Z_DATA_ERROR;
             {UPDATE}
             s.bitb := b;
             s.bitk := k;
             z.avail_in := n;
             inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
             z.next_in := p;
             s.write := q;
             inflate_codes := inflate_flush(s,z,r);
             exit;
           end;

     else  begin
             r := Z_STREAM_ERROR;
             {UPDATE}
             s.bitb := b;
             s.bitk := k;
             z.avail_in := n;
             inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
             z.next_in := p;
             s.write := q;
             inflate_codes := inflate_flush(s,z,r);
             exit;
           end;
    end; {case}
  end; {while true}
  {NEED_DUMMY_RETURN - Delphi2+ dumb compilers complain without this}
  inflate_codes := Z_STREAM_ERROR;
end;


{---------------------------------------------------------------------------}
procedure inflate_codes_free(c: pInflate_codes_state; var z: z_stream);
begin
  Z_FREE(z, c);
  {$ifdef DEBUG}
    Tracev('inflate:       codes free'#13#10);
  {$endif}
end;

end.
