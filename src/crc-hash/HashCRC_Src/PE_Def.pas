unit PE_Def;

interface

(*************************************************************************

 DESCRIPTION     :  Win32 PE file definitions

 REQUIREMENTS    :  TP5-7, D1-D7/9-10, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  o Johannes Plachy: The Portable Executable File Format, available at
                      http://www.csn.ul.ie/~caolan/publink/winresdump/winresdump/doc/pefile.html
                    o Matt Pietrek: An In-Depth Look into the Win32 Portable Executable File Format
                      http://msdn.microsoft.com/msdnmag/issues/02/02/PE/
                    o delphi-faq\16495.html
                    o WINNT.H

 REMARK          :  Modifications needed for WIN64

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     08.05.06  W.Ehrhardt  Initial version based on delphi-faq\16495.html
 0.11     09.05.06  we          Some additions, standard formating/names
**************************************************************************)


{$ifdef win32}
uses
  windows;
{$else}
type
  pdword = ^dword;
  dword  = longint;
{$endif}


const
  IMAGE_UNKNOWN_SIGNATURE = $0;
  IMAGE_DOS_SIGNATURE     = $5A4D;     {MZ}
  IMAGE_OS2_SIGNATURE     = $454E;     {NE}
  IMAGE_OS2_SIGNATURE_LE  = $454C;     {LE}
  IMAGE_VXD_SIGNATURE     = $454C;     {LE}
  IMAGE_NT_SIGNATURE      = $4550;     {PE}
  IMAGE_NT_SIGNATURE_L    = $00004550; {PE00}

const
  NE_IMAGE_DLL            = $8000;     {File is a DLL}

const
  IMAGE_NT_OPTIONAL_HDR_MAGIC    = $10B;
  IMAGE_NT_OPTIONAL_HDR32_MAGIC  = $10B;
  IMAGE_NT_OPTIONAL_HDR64_MAGIC  = $20B;
  IMAGE_ROM_OPTIONAL_HDR_MAGIC   = $107;

const
  IMAGE_FILE_RELOCS_STRIPPED     = $0001; {Relocation info stripd}
  IMAGE_FILE_EXECUTABLE_IMAGE    = $0002; {File is executable}
  IMAGE_FILE_LINE_NUMS_STRIPPED  = $0004; {Line numbers stripped}
  IMAGE_FILE_LOCAL_SYMS_STRIPPED = $0008; {Local symbols stripped}
  IMAGE_FILE_BYTES_REVERSED_LO   = $0080; {machine word bytes rev}
  IMAGE_FILE_32BIT_MACHINE       = $0100; {32 bit word machine}
  IMAGE_FILE_DEBUG_STRIPPED      = $0200; {Debug info stripped}
  IMAGE_FILE_SYSTEM              = $1000; {System File}
  IMAGE_FILE_DLL                 = $2000; {File is a DLL}
  IMAGE_FILE_BYTES_REVERSED_HI   = $8000; {machine word bytes rev}

const
  IMAGE_FILE_MACHINE_UNKNOWN     = $0;
  IMAGE_FILE_MACHINE_I386        = $14c;  {Intel 386}
  IMAGE_FILE_MACHINE_R3000B      = $160;  {MIPS big-endian}
  IMAGE_FILE_MACHINE_R3000L      = $162;  {MIPS little-endian}
  IMAGE_FILE_MACHINE_R4000       = $166;  {MIPS little-endian}
  IMAGE_FILE_MACHINE_R10000      = $168;  {MIPS little-endian}
  IMAGE_FILE_MACHINE_ALPHA       = $184;  {Alpha_AXP}
  IMAGE_FILE_MACHINE_POWERPC     = $1F0;  {IBM PowerPC Little-Endian}

const
  IMAGE_SIZEOF_SHORT_NAME          = 8;
  IMAGE_SIZEOF_SECTION_HEADER      = 40;
  IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
  IMAGE_RESOURCE_NAME_IS_STRING    = $80000000;
  IMAGE_RESOURCE_DATA_IS_DIRECTORY = $80000000;
  IMAGE_OFFSET_STRIP_HIGH          = $7FFFFFFF;

type
  PIMAGE_DOS_HEADER = ^TIMAGE_DOS_HEADER;
  TIMAGE_DOS_HEADER = packed record  {DOS .EXE header}
    e_magic    : word;               {Magic number}
    e_cblp     : word;               {Bytes on last page of file}
    e_cp       : word;               {Pages in file}
    e_crlc     : word;               {Relocations}
    e_cparhdr  : word;               {Size of header in paragraphs}
    e_minalloc : word;               {Minimum extra paragraphs needed}
    e_maxalloc : word;               {Maximum extra paragraphs needed}
    e_ss       : word;               {Initial (relative) SS value}
    e_sp       : word;               {Initial SP value}
    e_csum     : word;               {Checksum}
    e_ip       : word;               {Initial IP value}
    e_cs       : word;               {Initial (relative) CS value}
    e_lfarlc   : word;               {File address of relocation table}
    e_ovno     : word;               {Overlay number}
    e_res      : packed array[0..3] of word; {Reserved words}
    e_oemid    : word;               {OEM identifier (for e_oeminfo)}
    e_oeminfo  : word;               {OEM information; e_oemid specific}
    e_res2     : packed array[0..9] of word; {Reserved words}
    e_lfanew   : longint;            {File address of new exe header}
  end;

type
  PIMAGE_OS2_HEADER = ^TIMAGE_OS2_HEADER;
  TIMAGE_OS2_HEADER = packed record
    ne_magic       : word;      {Magic number}
    ne_ver         : char;      {Version number}
    ne_rev         : char;      {Revision number}
    ne_enttab      : word;      {Offset of Entry Table}
    ne_cbenttab    : word;      {Number of bytes in Entry Table}
    ne_crc         : longint;   {Checksum of whole file}
    ne_flags       : word;      {Flag word}
    ne_autodata    : word;      {Automatic data segment number}
    ne_heap        : word;      {Initial heap allocation}
    ne_stack       : word;      {Initial stack allocation}
    ne_csip        : longint;   {Initial CS:IP setting}
    ne_sssp        : longint;   {Initial SS:SP setting}
    ne_cseg        : word;      {Count of file segments}
    ne_cmod        : word;      {Entries in Module Reference Table}
    ne_cbnrestab   : word;      {Size of non-resident name table}
    ne_segtab      : word;      {Offset of Segment Table}
    ne_rsrctab     : word;      {Offset of Resource Table}
    ne_restab      : word;      {Offset of resident name table}
    ne_modtab      : word;      {Offset of Module Reference Table}
    ne_imptab      : word;      {Offset of Imported Names Table}
    ne_nrestab     : word;      {Offset of Non-resident Names Table}
    ne_cmovent     : word;      {Count of movable entries}
    ne_align       : word;      {Segment alignment shift count}
    ne_cres        : word;      {Count of resource segments}
    ne_exetyp      : word;      {Target Operating system}
    ne_flagsothers : word;      {Other .EXE flags}
    ne_pretthunks  : word;      {offset to return thunks}
    ne_psegrefbytes: word;      {offset to segment ref. bytes}
    ne_swaparea    : word;      {Minimum code swap area size}
    ne_expver      : word;      {Expected Windows version number}
  end;

type
  PIMAGE_VXD_HEADER = ^TIMAGE_VXD_HEADER;
  TIMAGE_VXD_HEADER = packed record
    e32_magic       : word;    {Magic number}
    e32_border      : byte;    {The byte ordering for the VXD}
    e32_worder      : byte;    {The word ordering for the VXD}
    e32_level       : dword;   {The EXE format level for now = 0}
    e32_cpu         : word;    {The CPU type}
    e32_os          : word;    {The OS type}
    e32_ver         : dword;   {Module version}
    e32_mflags      : dword;   {Module flags}
    e32_mpages      : dword;   {Module # pages}
    e32_startobj    : dword;   {Object # for instruction pointer}
    e32_eip         : dword;   {Extended instruction pointer}
    e32_stackobj    : dword;   {Object # for stack pointer}
    e32_esp         : dword;   {Extended stack pointer}
    e32_pagesize    : dword;   {VXD page size}
    e32_lastpagesize: dword;   {Last page size in VXD}
    e32_fixupsize   : dword;   {Fixup section size}
    e32_fixupsum    : dword;   {Fixup section checksum}
    e32_ldrsize     : dword;   {Loader section size}
    e32_ldrsum      : dword;   {Loader section checksum}
    e32_objtab      : dword;   {Object table offset}
    e32_objcnt      : dword;   {Number of objects in module}
    e32_objmap      : dword;   {Object page map offset}
    e32_itermap     : dword;   {Object iterated data map offset}
    e32_rsrctab     : dword;   {Offset of Resource Table}
    e32_rsrccnt     : dword;   {Number of resource entries}
    e32_restab      : dword;   {Offset of resident name table}
    e32_enttab      : dword;   {Offset of Entry Table}
    e32_dirtab      : dword;   {Offset of Module Directive Table}
    e32_dircnt      : dword;   {Number of module directives}
    e32_fpagetab    : dword;   {Offset of Fixup Page Table}
    e32_frectab     : dword;   {Offset of Fixup Record Table}
    e32_impmod      : dword;   {Offset of Import Module Name Table}
    e32_impmodcnt   : dword;   {NumEntries in Import Module Name Table}
    e32_impproc     : dword;   {Offset of Import Procedure Name Table}
    e32_pagesum     : dword;   {Offset of Per-Page Checksum Table}
    e32_datapage    : dword;   {Offset of Enumerated Data Pages}
    e32_preload     : dword;   {Number of preload pages}
    e32_nrestab     : dword;   {Offset of Non-resident Names Table}
    e32_cbnrestab   : dword;   {Size of Non-resident Name Table}
    e32_nressum     : dword;   {Non-resident Name Table Checksum}
    e32_autodata    : dword;   {Object # for automatic data object}
    e32_debuginfo   : dword;   {Offset of the debugging information}
    e32_debuglen    : dword;   {length of the debugging info. in bytes}
    e32_instpreload : dword;   {# of instance pages in preload section}
    e32_instdemand  : dword;   {# of inst pages in demand load section}
    e32_heapsize    : dword;   {Size of heap - for 16-bit apps}
    e32_res3        : packed  array[0..11] of byte;   {Reserved words}
    e32_winresoff   : dword;
    e32_winreslen   : dword;
    e32_devid       : word;    {Device ID for VxD}
    e32_ddkver      : word;    {DDK version for VxD}
  end;

type
  PIMAGE_DATA_DIRECTORY = ^TIMAGE_DATA_DIRECTORY;
  TIMAGE_DATA_DIRECTORY = packed record
    VirtualAddress  : dword;
    Size            : dword;
  end;

type
  PIMAGE_FILE_HEADER = ^TIMAGE_FILE_HEADER;
  TIMAGE_FILE_HEADER = packed record
    Machine              : word;
    NumberOfSections     : word;
    TimeDateStamp        : dword;
    PointerToSymbolTable : dword;
    NumberOfSymbols      : dword;
    SizeOfOptionalHeader : word;
    Characteristics      : word;
  end;

type
  PIMAGE_OPTIONAL_HEADER = ^TIMAGE_OPTIONAL_HEADER;
  TIMAGE_OPTIONAL_HEADER = packed record
    {Standard fields}
    Magic                      : word;
    MajorLinkerVersion         : byte;
    MinorLinkerVersion         : byte;
    SizeOfCode                 : dword;
    SizeOfInitializedData      : dword;
    SizeOfUninitializedData    : dword;
    AddressOfEntryPoint        : dword;
    BaseOfCode                 : dword;
    BaseOfData                 : dword;
    {NT additional fields}
    ImageBase                  : dword;
    SectionAlignment           : dword;
    FileAlignment              : dword;
    MajorOperatingSystemVersion: word;
    MinorOperatingSystemVersion: word;
    MajorImageVersion          : word;
    MinorImageVersion          : word;
    MajorSubsystemVersion      : word;
    MinorSubsystemVersion      : word;
    Reserved1                  : dword;
    SizeOfImage                : dword;
    SizeOfHeaders              : dword;
    CheckSum                   : dword;
    Subsystem                  : word;
    DllCharacteristics         : word;
    SizeOfStackReserve         : dword;
    SizeOfStackCommit          : dword;
    SizeOfHeapReserve          : dword;
    SizeOfHeapCommit           : dword;
    LoaderFlags                : dword;
    NumberOfRvaAndSizes        : dword;
    DataDirectory              : packed array[0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES-1] of TIMAGE_DATA_DIRECTORY;
  end;

type
  PIMAGE_ROM_OPTIONAL_HEADER = ^TIMAGE_ROM_OPTIONAL_HEADER;
  TIMAGE_ROM_OPTIONAL_HEADER = packed record
    Magic                  : word;
    MajorLinkerVersion     : byte;
    MinorLinkerVersion     : byte;
    SizeOfCode             : dword;
    SizeOfInitializedData  : dword;
    SizeOfUninitializedData: dword;
    AddressOfEntryPoint    : dword;
    BaseOfCode             : dword;
    BaseOfData             : dword;
    BaseOfBss              : dword;
    GprMask                : dword;
    CprMask                : packed array[0..3] of dword;
    GpValue                : dword;
  end;


type
  PIMAGE_SECTION_HEADER = ^TIMAGE_SECTION_HEADER;
  TIMAGE_SECTION_HEADER = packed record
    Name                : packed array[0..IMAGE_SIZEOF_SHORT_NAME-1] of char;
    PhysicalAddress     : dword;
    VirtualAddress      : dword;
    SizeOfRawData       : dword;
    PointerToRawData    : dword;
    PointerToRelocations: dword;
    PointerToLinenumbers: dword;
    NumberOfRelocations : word;
    NumberOfLinenumbers : word;
    Characteristics     : dword;
  end;

type
  PSECTION_HDR_ARRAY = ^TSECTION_HDR_ARRAY;
  TSECTION_HDR_ARRAY = packed array[1..$FF00 div sizeof(TIMAGE_SECTION_HEADER)] of TIMAGE_SECTION_HEADER;

type
  PIMAGE_NT_HEADERS = ^TIMAGE_NT_HEADERS;
  TIMAGE_NT_HEADERS = packed record
    Signature       : dword;
    FileHeader      : TIMAGE_FILE_HEADER;
    OptionalHeader  : TIMAGE_OPTIONAL_HEADER;
  end;

type
  PIMAGE_EXPORT_DIRECTORY = ^TIMAGE_EXPORT_DIRECTORY;
  TIMAGE_EXPORT_DIRECTORY = record
    Characteristics       : dword;
    TimeDateStamp         : dword;
    MajorVersion          : word;
    MinorVersion          : word;
    Name                  : dword;
    Base                  : dword;
    NumberOfFunctions     : dword;
    NumberOfNames         : dword;
    AddressOfFunctions    : pdword;
    AddressOfNames        : pdword;
    AddressOfNameOrdinals : pdword;
  end;

implementation

end.
