unit ZUtil;

(************************************************************************
  Configuration dependent utility and debugging function

  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Feb 2002
    - moved type declarations to ZLibH
    - Source code reformating/reordering
    - "const" strings in debug function
    - make code work under BP7/DPMI&Win
    - removed $ifdef CALLDOS
    - constant C_NL used in Trace calls for leading newline
  Mar 2005
    - Code cleanup for WWW upload
  May 2005
    - Trace: no writeln
    - Assert moved to zlibh
  Sep 2008
    - Avoid write for WIN32 GUI debug code (use OutputDebugString/MessageBox)
  Jul 2009
    - D12 fixes
*************************************************************************)


interface

{$x+}
{$I zconf.inc}

uses
  {$ifdef debug}
    {$ifdef WIN32}
      windows,  {must be listed in interface and before ZLibH}
                {otherwise some type related problems will be occur}
    {$endif}
  {$endif}
  ZLibH;

procedure zmemcpy(destp: pBytef; sourcep: pBytef; len: uInt);
function  zmemcmp(s1p, s2p: pBytef; len: uInt): int;
procedure zmemzero(destp: pBytef; len: uInt);
procedure zcfree(opaque: voidpf; ptr: voidpf);
function  zcalloc(opaque: voidpf; items: uInt; size: uInt): voidpf;

{Original: C macros}
function  Z_ALLOC(var strm: z_stream; items: uInt; size: uInt): voidpf;
procedure Z_FREE(var strm: z_stream; ptr: voidpf);
procedure TRY_FREE(var strm: z_stream; ptr: voidpf);

{$ifdef debug}
{Debug functions}
procedure z_error(const m: str255);
procedure Trace(const x: str255);
procedure Tracev(const x: str255);
procedure Tracevv(const x: str255);
procedure Tracevvv(const x: str255);
procedure Tracec(c: boolean; const x: str255);
procedure Tracecv(c: boolean; const x: str255);
function  IntToStr(value: longint): str255;
{$endif}


implementation

{$ifdef ver80}
  {$define Delphi16}
{$endif}

{$undef DPMI_OR_WIN}

{$ifdef ver70}
  {$define HugeMem}
  {$ifdef DPMI}
    {$define DPMI_OR_WIN}
    {$undef HugeMem} {*we 0202}
  {$endif}
  {$ifdef WINDOWS}
    {$define DPMI_OR_WIN}
    {$undef HugeMem} {*we 0202}
  {$endif}
{$endif}

{$ifdef ver60}
  {$define HugeMem}
{$endif}


{$ifdef Delphi16}
uses
  WinTypes,
  WinProcs;
{$endif}

{$ifndef FPC}
  {$ifdef DPMI_OR_WIN}
  uses
    WinAPI;
  {$endif}
{$endif}



{$ifdef HugeMem}
  {$define HEAP_LIST}
{$endif}

{$ifdef HEAP_LIST}

const
  MaxAllocEntries = 50;

{Allocation record which stores size of block for use with free}
type
  TMemRec = record
              orgvalue,
              value: pointer;
              size: longint;
            end;

const
  allocatedCount: 0..MaxAllocEntries = 0;

var
  allocatedList: array[0..MaxAllocEntries-1] of TMemRec;

{---------------------------------------------------------------------------}
function NewAllocation(ptr0, ptr: pointer; memsize: longint): boolean;
begin
  if (allocatedCount<MaxAllocEntries) and (ptr0<>nil) then begin
    with allocatedList[allocatedCount] do begin
      orgvalue := ptr0;
      value := ptr;
      size := memsize;
    end;
    inc(allocatedCount);    {we don't check for duplicate}
    NewAllocation := true;
  end
  else NewAllocation := false;
end;
{$endif}

{$ifdef HugeMem}

{we: It seems that Jacques Nomssi Nzali used parts of Duncan Murdoch's
contribution to MEMORY.SWG from SWAG for real mode.
Credits to dmurdoch@mast.queensu.ca (Duncan Murdoch)}

{The code below is extremely version specific to the TP 6/7 heap manager!!}

type
  LH = record
         L, H: word;
       end;

type
  PFreeRec = ^TFreeRec;
  TFreeRec = record
               next: PFreeRec;
               size: pointer;
             end;

type
  HugePtr = voidpf;


{---------------------------------------------------------------------------}
procedure IncPtr(var p: pointer; count: word);
  {-Increments pointer}
begin
  inc(LH(p).L,count);
  if LH(p).L < count then inc(LH(p).H,SelectorInc);
end;


{---------------------------------------------------------------------------}
function Normalized(p: pointer): pointer;
var
  count: word;
begin
  count := LH(p).L and $FFF0;
  Normalized := ptr(LH(p).H + (count shr 4), LH(p).L and $F);
end;


{---------------------------------------------------------------------------}
procedure FreeHuge(var p: HugePtr; size: longint);
const
  blocksize = $FFF0;
var
  block: word;
begin
  while size>0 do begin
    {block := minimum(size, blocksize);}
    if size > blocksize then block := blocksize else block := size;
    dec(size,block);
    FreeMem(p,block);
    IncPtr(p,block);    {we may get ptr($xxxx, $fff8) and 31 bytes left}
    p := Normalized(p); {to free, so we must normalize}
  end;
end;


{---------------------------------------------------------------------------}
function FreeMemHuge(ptr: pointer): boolean;
var
  i: integer; {-1..MaxAllocEntries}
begin
  FreeMemHuge := false;
  i := allocatedCount - 1;
  while i>=0 do begin
    if ptr=allocatedList[i].value then begin
      with allocatedList[i] do FreeHuge(orgvalue, size);
      Move(allocatedList[i+1], allocatedList[i], sizeof(TMemRec)*(allocatedCount - 1 - i));
      dec(allocatedCount);
      FreeMemHuge := true;
      break;
    end;
    dec(i);
  end;
end;



{---------------------------------------------------------------------------}
procedure GetMemHuge(var p: HugePtr; memsize: longint);
const
  blocksize = $FFF0;
var
  size: longint;
  prev,free: PFreeRec;
  save,temp: pointer;
  block: word;
begin
  p := nil;
  {Handle the easy cases first}
  if memsize > MaxAvail then exit
  else if memsize <= blocksize then begin
    GetMem(p, memsize);
    if not NewAllocation(p, p, memsize) then begin
      FreeMem(p, memsize);
      p := nil;
    end;
  end
  else begin
    size := memsize + 15;
    {Find the block that has enough space}
    prev := PFreeRec(@FreeList);
    free := prev^.next;
    while (free <> HeapPtr) and (ptr2int(free^.size) < size) do begin
      prev := free;
      free := prev^.next;
    end;

    {Now free points to a region with enough space; make it the first one and
    multiple allocations will be contiguous.}

    save := FreeList;
    FreeList := free;
    {In TP 6, this works; check against other heap managers}
    while size > 0 do begin
      {block := minimum(size, blocksize);}
      if size > blocksize then block := blocksize else block := size;
      dec(size,block);
      GetMem(temp,block);
    end;

    {We've got what we want now; just sort things out and restore the
    free list to normal}

    p := free;
    if prev^.next <> FreeList then begin
      prev^.next := FreeList;
      FreeList := save;
    end;

    if p<>nil then begin
      {return pointer with 0 offset}
      temp := p;
      if Ofs(p^)<>0 then p := ptr(seg(p^)+1,0);  {hack}
      if not NewAllocation(temp, p, memsize + 15) then begin
        FreeHuge(temp, size);
        p := nil;
      end;
    end;

  end;
end;

{$endif}


{---------------------------------------------------------------------------}
procedure zmemcpy(destp: pBytef; sourcep: pBytef; len: uInt);
begin
  Move(sourcep^, destp^, len);
end;


{---------------------------------------------------------------------------}
function zmemcmp(s1p, s2p: pBytef; len: uInt): int;
var
  j: uInt;
  source,
  dest: pBytef;
begin
  source := s1p;
  dest := s2p;
  for j := 0 to pred(len) do begin
    if source^<>dest^ then begin
      zmemcmp := 2*ord(source^ > dest^)-1;
      exit;
    end;
    inc(source);
    inc(dest);
  end;
  zmemcmp := 0;
end;


{---------------------------------------------------------------------------}
procedure zmemzero(destp: pBytef; len: uInt);
begin
  fillchar(destp^, len, 0);
end;


{---------------------------------------------------------------------------}
procedure zcfree(opaque: voidpf; ptr: voidpf);
{$ifdef Delphi16}
var
  Handle: THandle;
{$endif}
{$ifdef FPC}
var
  memsize: uint;
{$endif}
begin
  {$ifdef DPMI_OR_WIN}
     GlobalFreePtr(ptr);
  {$else}
    {$ifdef HugeMem}
      FreeMemHuge(ptr);
    {$else}
      {$ifdef Delphi16}
        Handle := GlobalHandle(HiWord(longint(ptr)));
        GlobalUnLock(Handle);
        GlobalFree(Handle);
      {$else}
        {$ifdef FPC}
          dec(puIntf(ptr));
          memsize := puIntf(ptr)^;
          FreeMem(ptr, memsize+sizeof(uInt));
        {$else}
          FreeMem(ptr);  {Delphi 2,3,4}
        {$endif}
      {$endif}
    {$endif}
  {$endif}
end;


{---------------------------------------------------------------------------}
function zcalloc(opaque: voidpf; items: uInt; size: uInt): voidpf;
var
  p: voidpf;
  memsize: uLong;
{$ifdef Delphi16}
  handle: THandle;
{$endif}
begin
  memsize := uLong(items) * uLong(size);
  {$ifdef DPMI_OR_WIN}
    p := GlobalAllocPtr(gmem_moveable, memsize);
  {$else}
    {$ifdef HugeMem}
      GetMemHuge(p, memsize);
    {$else}
      {$ifdef Delphi16}
        Handle := GlobalAlloc(HeapAllocFlags, memsize);
        p := GlobalLock(Handle);
      {$else}
        {$ifdef FPC}
          GetMem(p, memsize+sizeof(uInt));
          puIntf(p)^:= memsize;
          inc(puIntf(p));
        {$else}
          GetMem(p, memsize);  {Delphi: p := AllocMem(memsize);}
        {$endif}
      {$endif}
    {$endif}
  {$endif}
  zcalloc := p;
end;


{---------------------------------------------------------------------------}
function Z_ALLOC(var strm: z_stream; items: uInt; size: uInt): voidpf;
begin
  Z_ALLOC := strm.zalloc(strm.opaque, items, size);
end;


{---------------------------------------------------------------------------}
procedure Z_FREE(var strm: z_stream; ptr: voidpf);
begin
  strm.zfree(strm.opaque, ptr);
end;


{---------------------------------------------------------------------------}
procedure TRY_FREE(var strm: z_stream; ptr: voidpf);
begin
  {if @strm <> Z_NULL then}
    strm.zfree(strm.opaque, ptr);
end;


{$ifdef debug}


{$ifdef WIN32}
{$ifdef Unicode}
  {---------------------------------------------------------------------------}
  procedure z_error(const m: str255);
  var
    ax: string;
  begin
    if IsConsole then begin
      writeLn(output, m);
      write('Zlib - Halt...');
      readLn;
    end
    else
    begin
      ax := 'Zlib - Halt: '+string(m);
      MessageBox(0, PChar(ax), 'Error', MB_OK);
    end;
    halt(1);
  end;
  {---------------------------------------------------------------------------}
  procedure Trace(const x: str255);
  var
    ax: string;
    ls: integer;
  begin
    {$ifndef WIN32_USE_ODS}
      if IsConsole then begin
        write(x);
        exit;
      end;
    {$endif}
    {strip #13#10 from debug string}
    ax := string(x);
    ls := length(ax);
    if (ls>1) and (ax[ls]=#10) and (ax[ls-1]=#13) then dec(ls,2);
    ax := copy(ax,1,ls);
    OutputDebugString(PChar(ax));
  end;

{$else}
  {---------------------------------------------------------------------------}
  procedure z_error(const m: str255);
  var
    ax: ansistring;
  begin
    if IsConsole then begin
      writeLn(output, m);
      write('Zlib - Halt...');
      readLn;
    end
    else
    begin
      ax := 'Zlib - Halt: '+m;
      MessageBox(0, PChar8(ax), 'Error', MB_OK);
    end;
    halt(1);
  end;
  {---------------------------------------------------------------------------}
  procedure Trace(const x: str255);
  var
    ax: ansistring;
    ls: integer;
  begin
    {$ifndef WIN32_USE_ODS}
      if IsConsole then begin
        write(x);
        exit;
      end;
    {$endif}
    {strip #13#10 from debug string}
    ls := length(x);
    if (ls>1) and (x[ls]=#10) and (x[ls-1]=#13) then dec(ls,2);
    ax := copy(x,1,ls);
    OutputDebugString(PChar8(ax));
  end;

{$endif}
{$else}
{---------------------------------------------------------------------------}
procedure z_error(const m: str255);
begin
  writeLn(output, m);
  write('Zlib - Halt...');
  readLn;
  halt(1);
end;
{---------------------------------------------------------------------------}
procedure Trace(const x: str255);
begin
  write(x);
end;
{$endif}


{---------------------------------------------------------------------------}
procedure Tracev(const x: str255);
begin
 if z_verbose>0 then Trace(x);
end;


{---------------------------------------------------------------------------}
procedure Tracevv(const x: str255);
begin
  if z_verbose>1 then Trace(x);
end;


{---------------------------------------------------------------------------}
procedure Tracevvv(const x: str255);
begin
  if z_verbose>2 then Trace(x);
end;


{---------------------------------------------------------------------------}
procedure Tracec(c: boolean; const x: str255);
begin
  if (z_verbose>0) and c then Trace(x);
end;


{---------------------------------------------------------------------------}
procedure Tracecv(c: boolean; const x: str255);
begin
  if (z_verbose>1) and c then Trace(x);
end;


{---------------------------------------------------------------------------}
function IntToStr(value: longint): str255;
  {-Convert any integer type to a string }
var
  s: string[20];
begin
  Str(value:0, s);
  IntToStr := s;
end;

{$endif}

end.


