/*! @file       Matilda.h
    @version    2.0
    @brief      Internal adaptor
 */

#ifndef INCLUDED_Matilda
#define INCLUDED_Matilda

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
# pragma once
#endif

#ifdef _WIN32
# define snprintf   _snprintf
# define PRIu64     "I64u"
#else
# include <stdint.h>
#endif

#define CR_ASSERT(x)    

# define CLERROR 0
# define CLINFO  0
# define CLDEBUG 0
# define CLULTRA 0

struct ClTrace {
    inline ClTrace() { }
    inline ClTrace(const char *) { }
    inline ClTrace(const ClTrace &) { }
    inline void Trace(int,...) { }
    inline bool IsThisModuleTracing(int) { return false; }
};

#define NarrowString    std::string
#define WideString      std::wstring

namespace xplatform {
    unsigned long GetCurrentTickCount();
}

#define setCloseOnExec(x)   

#endif // INCLUDED_Matilda
