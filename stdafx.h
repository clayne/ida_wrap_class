// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once
#ifdef __NT__

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#endif


#include <hexrays.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <gdl.hpp>
#include <struct.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <search.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <demangle.hpp>

#include <cstring>
#include <cstdarg>
//#include <cstdint>

#include <iterator>
#include <string>
#include <vector>
#include <list>
#include <set>
#include <map>
#include <iostream>
#include <sstream>
