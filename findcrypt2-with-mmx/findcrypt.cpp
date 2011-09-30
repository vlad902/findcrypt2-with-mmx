// FindCrypt - find constants used in crypto algorithms
// Copyright 2006 Ilfak Guilfanov <ig@hexblog.com>
// Copyright 2011 Vlad Tsyrklevich <vlad@tsyrklevich.net>
// This is a freeware program.
// This copytight message must be kept intact.

// This plugin looks for constant arrays used in popular crypto algorithms.
// If a crypto algorithm is found, it will rename the appropriate locations
// of the program and put bookmarks on them.

// Version 2-with-mmx

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <moves.hpp>
#include <auto.hpp>
#include <set>

#include "findcrypt.hpp"

//--------------------------------------------------------------------------
// retrieve the first byte of the specified array
// take into account the byte sex
inline uchar get_first_byte(const array_info_t *a)
{
  const uchar *ptr = (const uchar *)a->array;
  if ( !inf.mf )
    return ptr[0];
  return ptr[a->elsize-1];
}

//--------------------------------------------------------------------------
// check that all constant arrays are distinct (no duplicates)
static void verify_constants(const array_info_t *consts)
{
  typedef std::set<qstring> strset_t;
  strset_t myset;
  for ( const array_info_t *ptr=consts; ptr->size != 0; ptr++ )
  {
    qstring s((char*)ptr->array, ptr->size);
    if ( !myset.insert(s).second )
      error("duplicate array %s!", ptr->name);
  }
}

//--------------------------------------------------------------------------
// match a constant array against the database at the specified address
static bool match_array_pattern(ea_t ea, const array_info_t *ai)
{
  uchar *ptr = (uchar *)ai->array;
  for ( size_t i=0; i < ai->size; i++ )
  {
    switch ( ai->elsize )
    {
      case 1:
        if ( get_byte(ea) != *(uchar*)ptr  )
          return false;
        break;
      case 2:
        if ( get_word(ea) != *(ushort*)ptr )
          return false;
        break;
      case 4:
        if ( get_long(ea) != *(uint32*)ptr )
          return false;
        break;
      case 8:
        if ( get_qword(ea)!= *(uint64*)ptr )
          return false;
        break;
      default:
        error("interr: unexpected array '%s' element size %d",
              ai->name, ai->elsize);
    }
    ptr += ai->elsize;
    ea  += ai->elsize;
  }
  return true;
}

//--------------------------------------------------------------------------
// match a sparse array against the database at the specified address
// NB: all sparse arrays must be word32!
static bool match_sparse_pattern(ea_t ea, const array_info_t *ai)
{
  const word32 *ptr = (const word32*)ai->array;
  if ( get_long(ea) != *ptr++ )
    return false;
  ea += 4;
  for ( size_t i=1; i < ai->size; i++ )
  {
    word32 c = *ptr++;
    if ( inf.mf )
      c = swap32(c);
    // look for the constant in the next N bytes
    const size_t N = 64;
    uchar mem[N+4];
    get_many_bytes(ea, mem, sizeof(mem));
    int j;
    for ( j=0; j < N; j++ )
      if ( *(uint32*)(mem+j) == c )
        break;
    if ( j == N )
      return false;
    ea += j + 4;
  }
  return true;
}

//--------------------------------------------------------------------------
// mark a location with the name of the algorithm
// use the first free slot for the marker
static void mark_location(ea_t ea, const char *name)
{
  char buf[MAXSTR];
  curloc cl;
  cl.ea = ea;
  cl.target = ea;
  cl.x = 0;
  cl.y = 5;
  cl.lnnum = 0;
  cl.flags = 0;
  // find free marked location slot
  int i;
  for ( i=1; i <= MAX_MARK_SLOT; i++ )
  {
    if ( cl.markdesc(i, buf, sizeof(buf)) <= 0 )
      break;
    // reuse old "Crypto: " slots
    if ( strncmp(buf, "Crypto: ", 7) == 0 && cl.markedpos(&i) == ea )
      break;
  }
  if ( i <= MAX_MARK_SLOT )
  {
    qsnprintf(buf, sizeof(buf), "Crypto: %s", name);
    cl.mark(i, NULL, buf);
  }
}

//--------------------------------------------------------------------------
// try to find constants at the given address range
static void recognize_constants(ea_t ea1, ea_t ea2)
{
  int array_count = 0, mmx_count = 0;
  show_wait_box("Searching for crypto constants...");
  for ( ea_t ea=ea1; ea < ea2; ea=nextaddr(ea) )
  {
    if ( (ea % 0x1000) == 0 )
    {
      showAddr(ea);
      if ( wasBreak() )
        break;
    }
    uchar b = get_byte(ea);
    // check against normal constants
    for ( const array_info_t *ptr=non_sparse_consts; ptr->size != 0; ptr++ )
    {
      if ( b != get_first_byte(ptr) )
        continue;
      if ( match_array_pattern(ea, ptr) )
      {
        msg("%a: found const array %s (used in %s)\n", ea, ptr->name, ptr->algorithm);
        mark_location(ea, ptr->algorithm);
        do_name_anyway(ea, ptr->name);
        array_count++;
        break;
      }
    }
    // check against sparse constants
    for ( const array_info_t *ptr=sparse_consts; ptr->size != 0; ptr++ )
    {
      if ( b != get_first_byte(ptr) )
        continue;
      if ( match_sparse_pattern(ea, ptr) )
      {
        msg("%a: found sparse constants for %s\n", ea, ptr->algorithm);
        mark_location(ea, ptr->algorithm);
        array_count++;
        break;
      }
    }
  }
  hide_wait_box();

  if(ph.id == PLFM_386)
  {
    show_wait_box("Searching for MMX AES instructions...");
    for ( ea_t ea=ea1; ea < ea2; ea=nextaddr(ea) )
    {
      if ( (ea % 0x1000) == 0 )
      {
        showAddr(ea);
        if ( wasBreak() )
          break;
      }
      uchar b = get_byte(ea);
      if( get_byte(ea) == 0x66 && get_byte(ea + 1) == 0x0f )
      {
        char * instruction = NULL;
        if( get_byte(ea + 2) == 0x38 )
        {
          if( get_byte(ea + 3) == 0xdb ) instruction = "AESIMC";
          if( get_byte(ea + 3) == 0xdc ) instruction = "AESENC";
          if( get_byte(ea + 3) == 0xdd ) instruction = "AESENCLAST";
          if( get_byte(ea + 3) == 0xde ) instruction = "AESDEC";
          if( get_byte(ea + 3) == 0xdf ) instruction = "AESDECLAST";
        }
        else if( get_byte(ea + 2) == 0x3a && get_byte(ea + 3) == 0xdf )
          instruction = "AESKEYGENASSIST";

        if(instruction)
        {
          // We distinguish between whether the bytes we've found are
          //  actual instructions or just possibly instructions
          if( get_item_head(ea) == ea && isCode(get_flags_novalue(ea)) )
            msg("%a: instructions is %s\n", ea, instruction);
          else
            msg("%a: may be %s\n", ea, instruction);
          mmx_count++;
        }
      }
    }
    hide_wait_box();
  }
  if ( array_count != 0 )
    msg("Found %d known constant arrays in total.\n", array_count);
  if ( mmx_count != 0 )
    msg("Found %d possible MMX AES* instructions.\n", mmx_count);
}

//--------------------------------------------------------------------------
// This callback is called for IDP notification events
static int idaapi search_callback(void * /*user_data*/, int event_id, va_list /*va*/)
{
  if ( event_id == processor_t::newfile ) // A new file is loaded (already)
    recognize_constants(inf.minEA, inf.maxEA);
  return 0;
}

//--------------------------------------------------------------------------
void idaapi run(int)
{
  ea_t ea1, ea2;
  read_selection(&ea1, &ea2); // if fails, inf.minEA and inf.maxEA will be used
  recognize_constants(ea1, ea2);
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
//  verify_constants(non_sparse_consts);
//  verify_constants(sparse_consts);
  // agree to work with any database
  hook_to_notification_point(HT_IDP, search_callback, NULL);
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  unhook_from_notification_point(HT_IDP, search_callback, NULL);
}

//--------------------------------------------------------------------------
char help[] = "Find crypt v2-with-mmx";
char comment[] = "Find crypt v2-with-mmx";
char wanted_name[] = "Find crypt v2-with-mmx";
char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,          // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
