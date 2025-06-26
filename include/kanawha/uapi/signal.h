#ifndef __KANAWHA__UAPI_SIGNAL_H__
#define __KANAWHA__UAPI_SIGNAL_H__

typedef unsigned long signal_id_t;

#define SIGNAL_XLIST(X)\
X(1, MEMFAULT)\
X(2, PROTFAULT)\
X(3, DECODEFAULT)\

#define DECLARE_SIGNAL_ID_CONSTANTS(__id, __NAME, ...)\
const static signal_id_t SIGNAL_ID_ ## __NAME = __id;
SIGNAL_XLIST(DECLARE_SIGNAL_ID_CONSTANTS)
#undef DECLARE_SIGNAL_ID_CONSTANTS

#ifdef KANAWHA_SIGNAL_UNDEF_XLISTS
#undef SIGNAL_XLIST
#endif

#endif
