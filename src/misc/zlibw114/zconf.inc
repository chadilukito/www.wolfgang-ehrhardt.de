{ --------------------------------- }
{ Configuration conditional defines }
{ --------------------------------- }

{ we 2005-05-22: StrictLong for FPC 2.0}
{ we 2005-08-03: $goto on for FPC      }
{ we 2008-09-02: conditional define WIN32_USE_ODS}
{ we 2015-09-07: UNIT_SCOPE, WIN32or64, FPC_Procvar}

{$define MAX_MATCH_IS_258}

{ Compile with -DMAXSEG_64K if the alloc function cannot allocate more
  than 64k bytes at a time (needed on systems with 16-bit int). }

{.$define MAXSEG_64K}
{$ifdef VER70}
  {$define MAXSEG_64K}
{$endif}

{$ifdef WIN32}
  {$define WIN32or64}
{$endif}

{$ifdef WIN64}
  {$define WIN32or64}
{$endif}


{$ifndef WIN32or64}
  {.$define UNALIGNED_OK}  { requires SizeOf(ush) = 2 ! }
{$endif}

{$undef UNALIGNED_OK}   {*we: do not use with 16 Bit code either!!   }
                        {Crash possible due to word memory access at }
                        {address with offset $FFFF in longest_match  }


{.$define DYNAMIC_CRC_TABLE}  {build CRC table or use static table   }
{.$define FASTEST}            {compression level is forced to 1      }
{.$define BUILDFIXED}         {build fixed tables or use inffixed.inc}

{.$define WIN32_USE_ODS}      {Always use OutputDebugStr for WIN32 even}
                              {for console mode programs.   WE Sep.2008}

{$undef D4Plus}
{$undef HaveAssert} {Assert support from system}
{$undef StrictLong} {Warning for longint const with MS bit}

{$ifdef WIN32or64}
  {$define Delphi32}
  {$ifdef VER120}
    {$define D4Plus}
  {$endif}
  {$ifdef VER130}
    {$define D4Plus}
  {$endif}
  {$ifdef CONDITIONALEXPRESSIONS}  {D6+}
    {$define D4Plus}
    {$ifdef ver230}
      {$define unit_scope}
    {$endif}
    {$ifdef ver240}
      {$define unit_scope}
    {$endif}
    {$ifdef ver250}
      {$define unit_scope}
    {$endif}
    {$ifdef ver260}
      {$define unit_scope}
    {$endif}
    {$ifdef ver270}
      {$define unit_scope}
    {$endif}
    {$ifdef ver280}
      {$define unit_scope}
    {$endif}
    {$ifdef ver290}
      {$define unit_scope}
    {$endif}
    {$ifdef ver300}
      {$define unit_scope}
    {$endif}
  {$endif}
{$endif}

{$ifdef DPMI}
  {$define MSDOS}
{$endif}

{$ifdef FPC}
  {$define Use32}
  {$undef DPMI}
  {$undef MSDOS}
  {$undef UNALIGNED_OK}     {requires sizeof(ush) = 2!}
  {$undef MAXSEG_64K}
  {$undef Delphi32}
  {$ifdef VER1}
    {$ifndef VER1_0}
      {FPC 1.9.x}
      {$define StrictLong}
    {$endif}
  {$endif}
  {$ifdef VER2}
    {$define StrictLong}
  {$endif}
  {$goto on}
  {$define HaveAssert}
  {$define FPC_ProcVar}
  {$ifdef FPC_DELPHI}
    {$undef FPC_ProcVar}
  {$endif}
  {$ifdef FPC_TP}
    {$undef FPC_ProcVar}
  {$endif}
  {$ifdef FPC_GPC}
    {$undef FPC_ProcVar}
  {$endif}
{$else}
  {$undef FPC_ProcVar}
{$endif}


{$ifdef D4Plus}
  {$define StrictLong}
  {$define HaveAssert}
{$endif}

{$ifdef VER100}
  {$define HaveAssert}
{$endif}


