/* safe_iop
 * License:: BSD
 * Author:: Will Drewry <redpig@dataspill.org>
 * 
 * To Do:
 * - try out type-marking the destination pointer
 * - rewrite safe_iopf to use type markup, maybe. maybe not.
 * - OPTIMIZE!
 * - Clean up TODOs
 * - Clean out legacy code and fix up style (line len, etc)
 * - Get PCC working
 * - Test out with other compilers
 * - Add tests for typeof() specific macros
 * - Optimize safe type casting to perform minimal operations
 * - Review existing tests for neglected cases
 * - Consider adding support for disabling safe_cast as it is expensive.
 * - Consider ways to do safe casting with operator awareness to
 *   allow cases where an addition of a negative signed value may be safe
 *   as a subtraction, for example. (Perhaps using checked type promotion
 *   similarly to compilers)
 *
 * History:
 * = 0.4
 * - Compiles under pcc (but not fully functional)
 * - Rewrote to support passing consts and compilers without typeof()
 * -- added safe_<op>x  -- primary interface
 * -- added safe_<op>v  -- varargs interface
 * - Add support for differently typed/signed operands in safe_iopf format
 * - Added negative tests to add T_<op>_*()s
 * - [BUG] Fixed signed addition. Two negatives were failing!
 * - Extended safe_iopf to support more types. Still needs more testing.
 * - Added more mixed interface tests
 * - Added safe type casting (automagically)
 * - Added basic speed tests (not accurate at all yet)
 * - Added safe_inc/safe_dec
 * - Licensed all subsequent work BSD for clarity of code ownership
 * = 0.3.1
 * - fixed typo/bug in safe_sadd (backported from 0.4.0/trunk above)
 * = 0.3
 * - solidified code into a smaller number of macros and functions
 * - added typeless functions using gcc magic (typeof)
 * - deprecrated old interfaces (-DSAFE_IOP_COMPAT)
 * - discover size maximums automagically
 * - separated test cases for easier understanding
 * - significantly expanded test cases
 * - derive type maximums and minimums internally (checked in testing)
 * = 0.2
 * - Removed dependence on twos complement arithmetic to allow macro-ized
 *   definitions
 * - Added (s)size_t support
 * - Added (u)int8,16,64 support
 * - Added portable inlining
 * - Added support for NULL result pointers
 * - Added support for header-only use (safe_iop.c only needed for safe_iopf)
 * = 0.1
 * - Initial release
 *
 * Contributors & thanks:
 * - peter@valchev.net for his review, comments, and enthusiasm
 * - Diego 'Flameeyes' Petteno for his analysis, use, and bug reporting
 * - thanks to Google for contributing some time
 *
 * Copyright (c) 2007,2008 Will Drewry <redpig@dataspill.org>
 * Some portions contributed by Google Inc., 2008.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* This library supplies a set of standard functions for performing and
 * checking safe integer operations. The code is based on examples from
 * https://www.securecoding.cert.org/confluence/display/seccode/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+overflow
 *
 * Inline functions are available for specific operations.  If the result
 * pointer is NULL, the function will still return 1 or 0 if it would
 * or would not overflow.  If multiple operations need to be performed,
 * safe_iopf provides a format-string driven model, but it does not yet support
 * non-32 bit operations
 *
 * NOTE: This code assumes int32_t to be signed.
 */
#ifndef _SAFE_IOP_H
#define _SAFE_IOP_H
#include <stdint.h> /* [u]int<bits>_t */
#include <sys/types.h> /* for [s]size_t */
#include <limits.h>  /* for CHAR_BIT */
#include <assert.h>  /* for type enforcement */
#include <stdarg.h> /* for variadic inlines */

#define SAFE_IOP_VERSION "0.4.0-pcc"

#if defined(__GNUC__)
#  define sio_inline static inline __attribute__ ((always_inline))
#else
#  define sio_inline static inline
#endif



typedef enum { SAFE_IOP_TYPE_U8 = 1,
               SAFE_IOP_TYPE_S8,
               SAFE_IOP_TYPE_U16,
               SAFE_IOP_TYPE_S16,
               SAFE_IOP_TYPE_U32,
               SAFE_IOP_TYPE_S32,
               SAFE_IOP_TYPE_U64,
               SAFE_IOP_TYPE_S64,
               SAFE_IOP_TYPE_DEFAULT = SAFE_IOP_TYPE_S32,
               } safe_type_t;

/* Largest data width supported by safe_iopf */
#define SAFE_IOPF_MAX_WIDTH sizeof(long long)
#define SAFE_IOP_TYPE_PREFIXES "us"

/* use a nice prefix :) */
#define __sio(x) OPAQUE_SAFE_IOP_PREFIX_ ## x
#define __sioi(x) OPAQUE_SAFE_IOP_PREFIXI_ ## x
#define OPAQUE_SAFE_IOP_PREFIX_var(x) OPAQUE_SAFE_IOP_PREFIX_VARIABLE_ ## x
#define OPAQUE_SAFE_IOP_PREFIX_m(x) OPAQUE_SAFE_IOP_PREFIX_MACRO_ ## x
#define OPAQUE_SAFE_IOP_PREFIX_f(x) OPAQUE_SAFE_IOP_PREFIX_FN_ ## x
#define OPAQUE_SAFE_IOP_PREFIX_val(_V,_T)  _V->v._T

#define OPAQUE_SAFE_IOP_PREFIXI_var(x) OPAQUE_SAFE_IOP_PREFIXI_VARIABLE_ ## x
#define OPAQUE_SAFE_IOP_PREFIXI_m(x) OPAQUE_SAFE_IOP_PREFIXI_MACRO_ ## x
#define OPAQUE_SAFE_IOP_PREFIXI_f(x) OPAQUE_SAFE_IOP_PREFIXI_FN_ ## x



/* A recursive macro which safely multiplies the given type together.
 * _ptr may be NULL.
 * mixed types or mixed sizes will unconditionally return 0;
 */
#define OPAQUE_SAFE_IOP_PREFIX_MACRO_smax(_type) \
  (_type)(~(_type)((_type) 1 << (_type)((sizeof(_type) * CHAR_BIT) - 1)))
#define OPAQUE_SAFE_IOP_PREFIX_MACRO_smin(_type) \
  (_type)(-(OPAQUE_SAFE_IOP_PREFIX_MACRO_smax(_type)) - 1)
#define OPAQUE_SAFE_IOP_PREFIX_MACRO_umax(_type) ((_type)(~((_type) 0)))


#ifdef __GNUC__
#define OPAQUE_SAFE_IOP_PREFIX_MACRO_is_signed(__sA) \
  (OPAQUE_SAFE_IOP_PREFIX_MACRO_smin(typeof(__sA)) <= ((typeof(__sA))0))
#define OPAQUE_SAFE_IOP_PREFIX_MACRO_type_enforce(__A, __B) \
  ((__sio(m)(is_signed)(__A) == \
    OPAQUE_SAFE_IOP_PREFIX_MACRO_is_signed(__B)) && \
   (sizeof(typeof(__A)) == sizeof(typeof(__B))))
#endif


/* We use some macro magic here to allow sign and type markup by the
 * client-programmer without relying on them to pass the explicit type.  This
 * works around the missing typeof extension but still puts the burden of most
 * checking and calculation on the compiler and not the runtime code.
 * This does require some markup from the programmer though:
 *   safe_addx(dst, sio_s32(a), sio_u16(b));
 * instead of
 *   safe_add(dst, a, b);
 * The latter is still supported, but it is not as portable.  If you will be
 * writing code to be compiled with PCC or another C99-focused compiler, you
 * should use the former.
 */
 struct sio_arg_t {
   uint8_t bits;
   _Bool   sign;
   union {
     uint8_t   u8;
      int8_t   s8;
     uint16_t u16;
      int16_t s16;
     uint32_t u32;
      int32_t s32;
     uint64_t u64;
      int64_t s64;
      /* used for transparent portability. bit sizes used for accessing */
      signed char    c;
      unsigned char uc;
      signed long    l;
      unsigned long ul;
      signed long long    ll;
      unsigned long long ull;
      size_t szt;
      ssize_t sszt;
      signed int    i;
      unsigned int ui;
   } v;
 };

#define sio_typeof_sio_s8(_a) int8_t
#define sio_signed_sio_s8(_a) 1
#define sio_valueof_sio_s8(_a) _a
#define sio_typeof_sio_u8(_a) uint8_t
#define sio_signed_sio_u8(_a) 0
#define sio_valueof_sio_u8(_a) _a

#define sio_typeof_sio_s16(_a) int16_t
#define sio_signed_sio_s16(_a) 1
#define sio_valueof_sio_s16(_a) _a
#define sio_typeof_sio_u16(_a) uint16_t
#define sio_signed_sio_u16(_a) 0
#define sio_valueof_sio_u16(_a) _a

#define sio_typeof_sio_s32(_a) int32_t
#define sio_signed_sio_s32(_a) 1
#define sio_valueof_sio_s32(_a) _a
#define sio_typeof_sio_u32(_a) uint32_t
#define sio_signed_sio_u32(_a) 0
#define sio_valueof_sio_u32(_a) _a

#define sio_typeof_sio_s64(_a) int64_t
#define sio_signed_sio_s64(_a) 1
#define sio_valueof_sio_s64(_a) _a
#define sio_typeof_sio_u64(_a) uint64_t
#define sio_signed_sio_u64(_a) 0
#define sio_valueof_sio_u64(_a) _a

#define sio_typeof_sio_sl(_a) signed long
#define sio_signed_sio_sl(_a) 1
#define sio_valueof_sio_sl(_a) _a
#define sio_typeof_sio_ul(_a) unsigned long
#define sio_signed_sio_ul(_a) 0
#define sio_valueof_sio_ul(_a) _a

#define sio_typeof_sio_sll(_a) signed long long
#define sio_signed_sio_sll(_a) 1
#define sio_valueof_sio_sll(_a) _a
#define sio_typeof_sio_ull(_a) unsigned long long
#define sio_signed_sio_ull(_a) 0
#define sio_valueof_sio_ull(_a) _a

#define sio_typeof_sio_si(_a) signed int
#define sio_signed_sio_si(_a) 1
#define sio_valueof_sio_si(_a) _a
#define sio_typeof_sio_ui(_a) unsigned int
#define sio_signed_sio_ui(_a) 0
#define sio_valueof_sio_ui(_a) _a


#define sio_typeof_sio_sc(_a) signed char
#define sio_signed_sio_sc(_a) 1
#define sio_valueof_sio_sc(_a) _a
#define sio_typeof_sio_uc(_a) unsigned char
#define sio_signed_sio_uc(_a) 0
#define sio_valueof_sio_uc(_a) _a

#define sio_typeof_sio_sszt(_a) ssize_t
#define sio_signed_sio_sszt(_a) 1
#define sio_valueof_sio_sszt(_a) _a
#define sio_typeof_sio_szt(_a) size_t
#define sio_signed_sio_szt(_a) 0
#define sio_valueof_sio_szt(_a) _a


#ifdef __GNUC__
#define safe_add(_dst, _A, _B) ({ \
  /* Protect against side effects */ \
  typeof(_A) __sio(var)(_a) = (_A); \
  typeof(_B) __sio(var)(_b) = (_B); \
  typeof(_A) *__sio(var)(_ptr) = (_dst); \
  _Bool __sio(var)(ok) =  \
    (sio_safe_cast(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                   __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) ? \
      ( __sio(m)(is_signed)(_A) ? \
          safe_sadd(__sio(var)(_ptr),\
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) \
        :  \
          safe_uadd(__sio(var)(_ptr), \
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b))) \
      : 0 ); \
   __sio(var)(ok); \
})

#define safe_sub(_dst, _a, _b) ({ \
  typeof(_a) __sio(var)(sub_a) = (_a); \
  typeof(_b) __sio(var)(sub_b) = (_b); \
  _Bool __sio(var)(ok) = 1; \
  struct sio_arg_t __sio(var)(a) = {0}, __sio(var)(b) = {0}; \
  __sio(var)(a).bits = sizeof(typeof(__sio(var)(sub_a)))*CHAR_BIT; \
  __sio(var)(b).bits = sizeof(typeof(__sio(var)(sub_b)))*CHAR_BIT; \
  __sio(var)(a).sign = __sio(m)(is_signed)(__sio(var)(sub_a)); \
  __sio(var)(b).sign = __sio(m)(is_signed)(__sio(var)(sub_b)); \
  switch (__sio(var)(a).bits) { \
    case 8: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s8 = __sio(var)(sub_a); \
      else                    __sio(var)(a).v.u8 = __sio(var)(sub_a); \
      break; \
    case 16: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s16 = __sio(var)(sub_a); \
      else                    __sio(var)(a).v.u16 = __sio(var)(sub_a); \
      break; \
    case 32: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s32 = __sio(var)(sub_a); \
      else                    __sio(var)(a).v.u32 = __sio(var)(sub_a); \
      break; \
    case 64: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s64 = __sio(var)(sub_a); \
      else                    __sio(var)(a).v.u64 = __sio(var)(sub_a); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  switch (__sio(var)(b).bits) { \
    case 8: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s8 = __sio(var)(sub_b); \
      else                    __sio(var)(b).v.u8 = __sio(var)(sub_b); \
      break; \
    case 16: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s16 = __sio(var)(sub_b); \
      else                    __sio(var)(b).v.u16 = __sio(var)(sub_b); \
      break; \
    case 32: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s32 = __sio(var)(sub_b); \
      else                    __sio(var)(b).v.u32 = __sio(var)(sub_b); \
      break; \
    case 64: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s64 = __sio(var)(sub_b); \
      else                    __sio(var)(b).v.u64 = __sio(var)(sub_b); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  if (__sio(var)(ok))  \
    __sio(var)(ok) = safe_subx(_dst,  &__sio(var)(a), &__sio(var)(b)); \
  __sio(var)(ok); \
})

#define safe_mul(_dst, _a, _b) ({ \
  typeof(_a) __sio(var)(mul_a) = (_a); \
  typeof(_b) __sio(var)(mul_b) = (_b); \
  _Bool __sio(var)(ok) = 1; \
  struct sio_arg_t __sio(var)(a) = {0}, __sio(var)(b) = {0}; \
  __sio(var)(a).bits = sizeof(typeof(__sio(var)(mul_a)))*CHAR_BIT; \
  __sio(var)(b).bits = sizeof(typeof(__sio(var)(mul_b)))*CHAR_BIT; \
  __sio(var)(a).sign = __sio(m)(is_signed)(__sio(var)(mul_a)); \
  __sio(var)(b).sign = __sio(m)(is_signed)(__sio(var)(mul_b)); \
  switch (__sio(var)(a).bits) { \
    case 8: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s8 = __sio(var)(mul_a); \
      else                    __sio(var)(a).v.u8 = __sio(var)(mul_a); \
      break; \
    case 16: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s16 = __sio(var)(mul_a); \
      else                    __sio(var)(a).v.u16 = __sio(var)(mul_a); \
      break; \
    case 32: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s32 = __sio(var)(mul_a); \
      else                    __sio(var)(a).v.u32 = __sio(var)(mul_a); \
      break; \
    case 64: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s64 = __sio(var)(mul_a); \
      else                    __sio(var)(a).v.u64 = __sio(var)(mul_a); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  switch (__sio(var)(b).bits) { \
    case 8: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s8 = __sio(var)(mul_b); \
      else                    __sio(var)(b).v.u8 = __sio(var)(mul_b); \
      break; \
    case 16: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s16 = __sio(var)(mul_b); \
      else                    __sio(var)(b).v.u16 = __sio(var)(mul_b); \
      break; \
    case 32: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s32 = __sio(var)(mul_b); \
      else                    __sio(var)(b).v.u32 = __sio(var)(mul_b); \
      break; \
    case 64: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s64 = __sio(var)(mul_b); \
      else                    __sio(var)(b).v.u64 = __sio(var)(mul_b); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  if (__sio(var)(ok))  \
    __sio(var)(ok) = safe_mulx(_dst,  &__sio(var)(a), &__sio(var)(b)); \
  __sio(var)(ok); \
})

#define safe_mod(_dst, _a, _b) ({ \
  typeof(_a) __sio(var)(mod_a) = (_a); \
  typeof(_b) __sio(var)(mod_b) = (_b); \
  _Bool __sio(var)(ok) = 1; \
  struct sio_arg_t __sio(var)(a) = {0}, __sio(var)(b) = {0}; \
  __sio(var)(a).bits = sizeof(typeof(__sio(var)(mod_a)))*CHAR_BIT; \
  __sio(var)(b).bits = sizeof(typeof(__sio(var)(mod_b)))*CHAR_BIT; \
  __sio(var)(a).sign = __sio(m)(is_signed)(__sio(var)(mod_a)); \
  __sio(var)(b).sign = __sio(m)(is_signed)(__sio(var)(mod_b)); \
  switch (__sio(var)(a).bits) { \
    case 8: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s8 = __sio(var)(mod_a); \
      else                    __sio(var)(a).v.u8 = __sio(var)(mod_a); \
      break; \
    case 16: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s16 = __sio(var)(mod_a); \
      else                    __sio(var)(a).v.u16 = __sio(var)(mod_a); \
      break; \
    case 32: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s32 = __sio(var)(mod_a); \
      else                    __sio(var)(a).v.u32 = __sio(var)(mod_a); \
      break; \
    case 64: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s64 = __sio(var)(mod_a); \
      else                    __sio(var)(a).v.u64 = __sio(var)(mod_a); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  switch (__sio(var)(b).bits) { \
    case 8: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s8 = __sio(var)(mod_b); \
      else                    __sio(var)(b).v.u8 = __sio(var)(mod_b); \
      break; \
    case 16: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s16 = __sio(var)(mod_b); \
      else                    __sio(var)(b).v.u16 = __sio(var)(mod_b); \
      break; \
    case 32: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s32 = __sio(var)(mod_b); \
      else                    __sio(var)(b).v.u32 = __sio(var)(mod_b); \
      break; \
    case 64: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s64 = __sio(var)(mod_b); \
      else                    __sio(var)(b).v.u64 = __sio(var)(mod_b); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  if (__sio(var)(ok))  \
    __sio(var)(ok) = safe_modx(_dst,  &__sio(var)(a), &__sio(var)(b)); \
  __sio(var)(ok); \
})

#define safe_div(_dst, _a, _b) ({ \
  typeof(_a) __sio(var)(div_a) = (_a); \
  typeof(_b) __sio(var)(div_b) = (_b); \
  _Bool __sio(var)(ok) = 1; \
  struct sio_arg_t __sio(var)(a) = {0}, __sio(var)(b) = {0}; \
  __sio(var)(a).bits = sizeof(typeof(__sio(var)(div_a)))*CHAR_BIT; \
  __sio(var)(b).bits = sizeof(typeof(__sio(var)(div_b)))*CHAR_BIT; \
  __sio(var)(a).sign = __sio(m)(is_signed)(__sio(var)(div_a)); \
  __sio(var)(b).sign = __sio(m)(is_signed)(__sio(var)(div_b)); \
  switch (__sio(var)(a).bits) { \
    case 8: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s8 = __sio(var)(div_a); \
      else                    __sio(var)(a).v.u8 = __sio(var)(div_a); \
      break; \
    case 16: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s16 = __sio(var)(div_a); \
      else                    __sio(var)(a).v.u16 = __sio(var)(div_a); \
      break; \
    case 32: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s32 = __sio(var)(div_a); \
      else                    __sio(var)(a).v.u32 = __sio(var)(div_a); \
      break; \
    case 64: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s64 = __sio(var)(div_a); \
      else                    __sio(var)(a).v.u64 = __sio(var)(div_a); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  switch (__sio(var)(b).bits) { \
    case 8: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s8 = __sio(var)(div_b); \
      else                    __sio(var)(b).v.u8 = __sio(var)(div_b); \
      break; \
    case 16: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s16 = __sio(var)(div_b); \
      else                    __sio(var)(b).v.u16 = __sio(var)(div_b); \
      break; \
    case 32: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s32 = __sio(var)(div_b); \
      else                    __sio(var)(b).v.u32 = __sio(var)(div_b); \
      break; \
    case 64: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s64 = __sio(var)(div_b); \
      else                    __sio(var)(b).v.u64 = __sio(var)(div_b); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  if (__sio(var)(ok))  \
    __sio(var)(ok) = safe_divx(_dst,  &__sio(var)(a), &__sio(var)(b)); \
  __sio(var)(ok); \
})

#define safe_shl(_dst, _a, _b) ({ \
  typeof(_a) __sio(var)(shl_a) = (_a); \
  typeof(_b) __sio(var)(shl_b) = (_b); \
  _Bool __sio(var)(ok) = 1; \
  struct sio_arg_t __sio(var)(a) = {0}, __sio(var)(b) = {0}; \
  __sio(var)(a).bits = sizeof(typeof(__sio(var)(shl_a)))*CHAR_BIT; \
  __sio(var)(b).bits = sizeof(typeof(__sio(var)(shl_b)))*CHAR_BIT; \
  __sio(var)(a).sign = __sio(m)(is_signed)(__sio(var)(shl_a)); \
  __sio(var)(b).sign = __sio(m)(is_signed)(__sio(var)(shl_b)); \
  switch (__sio(var)(a).bits) { \
    case 8: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s8 = __sio(var)(shl_a); \
      else                    __sio(var)(a).v.u8 = __sio(var)(shl_a); \
      break; \
    case 16: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s16 = __sio(var)(shl_a); \
      else                    __sio(var)(a).v.u16 = __sio(var)(shl_a); \
      break; \
    case 32: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s32 = __sio(var)(shl_a); \
      else                    __sio(var)(a).v.u32 = __sio(var)(shl_a); \
      break; \
    case 64: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s64 = __sio(var)(shl_a); \
      else                    __sio(var)(a).v.u64 = __sio(var)(shl_a); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  switch (__sio(var)(b).bits) { \
    case 8: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s8 = __sio(var)(shl_b); \
      else                    __sio(var)(b).v.u8 = __sio(var)(shl_b); \
      break; \
    case 16: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s16 = __sio(var)(shl_b); \
      else                    __sio(var)(b).v.u16 = __sio(var)(shl_b); \
      break; \
    case 32: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s32 = __sio(var)(shl_b); \
      else                    __sio(var)(b).v.u32 = __sio(var)(shl_b); \
      break; \
    case 64: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s64 = __sio(var)(shl_b); \
      else                    __sio(var)(b).v.u64 = __sio(var)(shl_b); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  if (__sio(var)(ok))  \
    __sio(var)(ok) = safe_shlx(_dst,  &__sio(var)(a), &__sio(var)(b)); \
  __sio(var)(ok); \
})

#define safe_shr(_dst, _a, _b) ({ \
  typeof(_a) __sio(var)(shr_a) = (_a); \
  typeof(_b) __sio(var)(shr_b) = (_b); \
  _Bool __sio(var)(ok) = 1; \
  struct sio_arg_t __sio(var)(a) = {0}, __sio(var)(b) = {0}; \
  __sio(var)(a).bits = sizeof(typeof(__sio(var)(shr_a)))*CHAR_BIT; \
  __sio(var)(b).bits = sizeof(typeof(__sio(var)(shr_b)))*CHAR_BIT; \
  __sio(var)(a).sign = __sio(m)(is_signed)(__sio(var)(shr_a)); \
  __sio(var)(b).sign = __sio(m)(is_signed)(__sio(var)(shr_b)); \
  switch (__sio(var)(a).bits) { \
    case 8: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s8 = __sio(var)(shr_a); \
      else                    __sio(var)(a).v.u8 = __sio(var)(shr_a); \
      break; \
    case 16: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s16 = __sio(var)(shr_a); \
      else                    __sio(var)(a).v.u16 = __sio(var)(shr_a); \
      break; \
    case 32: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s32 = __sio(var)(shr_a); \
      else                    __sio(var)(a).v.u32 = __sio(var)(shr_a); \
      break; \
    case 64: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s64 = __sio(var)(shr_a); \
      else                    __sio(var)(a).v.u64 = __sio(var)(shr_a); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  switch (__sio(var)(b).bits) { \
    case 8: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s8 = __sio(var)(shr_b); \
      else                    __sio(var)(b).v.u8 = __sio(var)(shr_b); \
      break; \
    case 16: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s16 = __sio(var)(shr_b); \
      else                    __sio(var)(b).v.u16 = __sio(var)(shr_b); \
      break; \
    case 32: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s32 = __sio(var)(shr_b); \
      else                    __sio(var)(b).v.u32 = __sio(var)(shr_b); \
      break; \
    case 64: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s64 = __sio(var)(shr_b); \
      else                    __sio(var)(b).v.u64 = __sio(var)(shr_b); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  if (__sio(var)(ok))  \
    __sio(var)(ok) = safe_shrx(_dst,  &__sio(var)(a), &__sio(var)(b)); \
  __sio(var)(ok); \
})


#endif /* __GNUC__ */

/*** Same-type addition macros ***/
#define safe_uadd(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) ( \
  (/* safety check */ \
   ((_a_type)(_b) <= \
      ((_a_type)(__sio(m)(umax)(_a_type) - \
       (_a))) ? 1 : 0)) \
  ? \
    ((_ptr) ? \
      *((_a_type *)(_ptr)) = ((_a) + (_b)), 1 : 1) \
  : 0)


/* Example call: safe_sadd(NULL, dst, sio_s32(blah), sio_s32(foo)) */
/* ( (tests) ? (ptr ? ptr = ...),1 : 0; ) */
#define safe_sadd(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ( /* Do tests here */ \
    ((((_b) > (_a_type)0) && \
       ((_a) > (_a_type)0)) \
     ? /*>0*/  \
       ((_a) > \
         (_a_type)(__sio(m)(smax)(_a_type) - \
         (_b)) ? 0 : 1) \
     : \
       /* <0 */ \
       ((!((_b) > (_a_type)0) && \
                !((_a) > (_a_type)0)) ? \
         (((_a) < \
           (_a_type)(__sio(m)(smin)(_a_type) - \
                             (_b))) ? 0 : 1) : 1) \
     ) \
   ? /* Now assign if needed */ \
     ((_ptr) ? \
       *((_a_type *)(_ptr)) = ((_a) + (_b)),\
       1 \
       : \
       1 \
     ) \
   : \
     0 \
)

/*** Same-type subtraction macros ***/
#define safe_usub(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((_a) >= (_b) ? ((_ptr) ? *((_a_type*)(_ptr)) = ((_a) - (_b)),1 : 1) : 0 )

#define safe_ssub(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) ( \
  (!((_b) <= 0 && (_a) > (__sio(m)(smax)(_a_type) + (_b))) && \
   !((_b) > 0 && (_a) < (__sio(m)(smin)(_a_type) + (_b)))) \
  ? \
    ((_ptr) ? *((_a_type*)(_ptr)) = ((_a) - (_b)), 1 : 1) \
  : \
    0)


/*** Same-type multiplication macros ***/
#define safe_umul(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) ( \
  (!(_b) || (_a) <= (__sio(m)(umax)(_a_type) / (_b))) \
  ? \
    (((_ptr)) ? *((_a_type*)(_ptr)) = (_a) * (_b),1 : 1) \
  : \
    0)

#define safe_smul(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((((_a) > 0) ?  /* a is positive */ \
    (((_b) > 0) ?  /* b and a are positive */ \
       (((_a) > (__sio(m)(smax)(_a_type) / (_b))) ? 0 : 1) \
     : /* a positive, b non-positive */ \
       (((_b) < (__sio(m)(smin)(_a_type) / (_a))) ? 0 : 1)) \
   : /* a is non-positive */ \
    (((_b) > 0) ? /* a is non-positive, b is positive */ \
      (((_a) < (__sio(m)(smin)(_a_type) / (_b))) ? 0 : 1) \
     : /* a and b are non-positive */ \
      ((((_a) != 0) && ((_b) < (__sio(m)(smax)(_a_type) / (_a)))) ? 0 : 1) \
      ) \
  ) /* end if a and b are non-positive */ \
  ? \
    ((_ptr) ? *((_a_type*)(_ptr)) = ((_a) * (_b)),1 : 1) \
  : 0)

/*** Same-type division macros ***/

/* div-by-zero is the only thing addressed */
#define safe_udiv(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_b) != 0) ? (((_ptr)) ? *((_a_type*)(_ptr)) = ((_a) / (_b)),1 : 1) : 0)

/* Addreses div by zero and smin -1 */
#define safe_sdiv(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_b) != 0 && (((_a) != __sio(m)(smin)(_a_type)) || ((_b) != (_a_type)-1))) \
   ? \
    (((_ptr)) ? *((_a_type*)(_ptr)) = ((_a) / (_b)),1 : 1) \
  : \
    0 \
  ) \


/*** Same-type modulo macros ***/
/* mod-by-zero is the only thing addressed */
#define safe_umod(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_b) != 0) ? (((_ptr)) ? *((_a_type*)(_ptr)) = ((_a) % (_b)),1 : 1) : 0)

/* Addreses mod by zero and smin -1 */
#define safe_smod(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_b) != 0 && (((_a) != __sio(m)(smin)(_a_type)) || ((_b) != (_a_type)-1))) \
   ? \
    (((_ptr)) ? *((_a_type*)(_ptr)) = ((_a) % (_b)),1 : 1) \
  : \
    0 \
  ) \

/*** Same-type left-shift macros ***/
#define safe_sshl(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((((_a) < 0) || \
      ((_b) < 0) || \
      ((_b) >= sizeof(_a_type)*CHAR_BIT) || \
      ((_a) > (__sio(m)(smax)(_a_type) >> (_b)))) ? \
    0 \
  : (((_ptr)) ? *((_a_type*)(_ptr)) = (_a) << (_b),1 : 1))

#define safe_ushl(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((((_b) >= sizeof(_a_type)*CHAR_BIT) || \
      ((_a) > (__sio(m)(umax)(_a_type) >> (_b)))) ? \
    0 \
  : \
    (((_ptr)) ? *((_a_type*)(_ptr)) = (_a) << (_b),1 :  1))

/*** Same-type right-shift macros ***/
/* XXX: CERT doesnt recommend failing on -a, but it is undefined */
#define safe_sshr(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((!((_a) > 0 || (_a) == 0) || \
      !((_b) > 0 || (_b) == 0) || \
      ((_b) >= sizeof(_a_type)*CHAR_BIT)) ? \
    0 \
  : \
    (((_ptr)) ? *((_a_type*)(_ptr)) = (_a) >> (_b),1 : 1) \
  )

/* this doesn't whine if 0 >> n. */
#define safe_ushr(_ptr, _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_b) >= (sizeof(_a_type)*CHAR_BIT)) ? \
    0 : (((_ptr)) ? *((_a_type*)(_ptr)) = ((_a) >> (_b)),1 : 1))

/*** Actual interface declarations ***/
#define safe_inc(_type, _p) safe_addx(_p, sio_##_type(*_p), sio_##_type(1))
#define safe_dec(_type, _p) safe_subx(_p, sio_##_type(*_p), sio_##_type(1))

#define sio_safe_cast(_a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((sizeof(_a_type) == sizeof(_b_type)) \
  ? \
    /* sign change */ \
    ((!_a_sign && !_b_sign) ? \
      1 \
    : \
      ((_a_sign && _b_sign) \
      ? \
        1 \
      : \
        ((!_a_sign && _b_sign) \
        ? \
          (((_b) > (_b_type)0 || (_b) == (_b_type)0) ? 1 : 0) \
        : \
          ((_a_sign && !_b_sign) \
          ? \
      /* since they are the same size, the comparison cast should be safe */ \
            (((_b) < (_b_type)__sio(m)(smax)(_a_type) || \
             (_b) == (_b_type)__sio(m)(smax)(_a_type)) ? 1: 0) \
          : \
            0 \
          ) \
        ) \
      ) \
    ) \
  : \
    ((sizeof(_a_type) > sizeof(_b_type)) \
    ? \
      /* cast up: this allows -1, e.g., which means extension. */ \
      /* Is that _really_ safe ? */ \
      ((!_a_sign && !_b_sign) \
      ? \
        1 \
      : \
        ((_a_sign && _b_sign) \
        ? \
          1 \
        : \
          ((!_a_sign && _b_sign) \
          ? \
            (((_b) == (_b_type)0 || (_b) > (_b_type)0) ? 1 : 0)\
          : \
            ((_a_sign && !_b_sign) \
            ? \
              /* this is true by default */ \
              ((__sio(m)(smax)(_a_type) >= __sio(m)(umax)(_b_type)) ? 1 : 0) \
            : \
              0 \
            ) \
          ) \
        ) \
      ) \
    : \
      /* This will safely truncate given that smax(a) <= umax(b) */ \
      (((_b) < (_b_type)__sio(m)(smax)(_a_type) || \
          (_b) == (_b_type)__sio(m)(smax)(_a_type)) \
      ? \
        1 \
      : \
        ((sizeof(_a_type) < sizeof(_b_type)) \
        ? \
          /* cast down (loss of precision) */ \
          ((!_a_sign && !_b_sign) \
          ? \
            (((_b) == (_b_type)__sio(m)(umax)(_a_type)) \
            ? \
              1 \
            : \
              (((_b) < (_b_type)__sio(m)(umax)(_a_type)) ? 1 : 0) \
            ) \
          : \
            ((_a_sign && _b_sign) \
            ? \
              ((((_b) > (_b_type)__sio(m)(smin)(_a_type) || \
                 (_b) == (_b_type)__sio(m)(smin)(_a_type)) && \
                ((_b) < (_b_type)__sio(m)(smax)(_a_type) || \
                 (_b) == (_b_type)__sio(m)(smax)(_a_type))) \
              ? \
                1 \
              : \
                0 \
              ) \
            : \
              ((!_a_sign && _b_sign) \
              ? \
                /* this should safely extend */ \
                ((((_b) > (_b_type)0 || (_b) == (_b_type)0) && \
                 (((_b) < (_b_type)__sio(m)(umax)(_a_type)) || \
                  ((_b) == (_b_type)__sio(m)(umax)(_a_type)))) \
                ? \
                  1 \
                : \
                  0 \
                ) \
              : \
                ((_a_sign && !_b_sign) \
                ? \
                  /* this should safely extend */ \
                  (((_b) < (_b_type)__sio(m)(smax)(_a_type) || \
                    (_b) == (_b_type)__sio(m)(smax)(_a_type)) \
                  ? \
                    1 \
                  : \
                    0 \
                  ) \
                : \
                  0 \
                ) \
              ) \
            ) \
          ) \
        : \
          0 \
        ) \
      ) \
    ) \
  )


 


#define safe_addx(_ptr, _a, _b) \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    ( sio_signed_##_a ? \
        safe_sadd(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
      :  \
        safe_uadd(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0)

#define safe_subx(_ptr, _a, _b) \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    ( sio_signed_##_a ? \
        safe_ssub(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
      :  \
        safe_usub(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0)

#define safe_mulx(_ptr, _a, _b) \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    ( sio_signed_##_a ? \
        safe_smul(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
      :  \
        safe_umul(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0)

#define safe_divx(_ptr, _a, _b) \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    ( sio_signed_##_a ? \
        safe_sdiv(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
      :  \
        safe_udiv(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0)

#define safe_modx(_ptr, _a, _b) \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    ( sio_signed_##_a ? \
        safe_smod(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
      :  \
        safe_umod(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0)

#define safe_shlx(_ptr, _a, _b) \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    ( sio_signed_##_a ? \
        safe_sshl(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
      :  \
        safe_ushl(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0)

#define safe_shrx(_ptr, _a, _b) \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    ( sio_signed_##_a ? \
        safe_sshr(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
      :  \
        safe_ushr(_ptr, sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                        sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0)

/*
__sioi(m)(declare_safe_op)(sub)
__sioi(m)(declare_safe_op)(mul)
__sioi(m)(declare_safe_op)(div)
__sioi(m)(declare_safe_op)(mod)
__sioi(m)(declare_safe_op)(shl)
__sioi(m)(declare_safe_op)(shr)
*/

#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_declare_safe_op


/* XXX: These probably can't be inlined  and should be moved to
 * safe_iop.c
 */
#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_declare_safe_opv(_OP) \
  static inline _Bool safe_##_OP##v(void *dst, size_t args, ...) { \
    struct sio_arg_t total = {0}; \
    va_list ap; \
 \
    va_start(ap, args); \
    /* Grab the first argument so we can prep total */ \
    { \
      const struct sio_arg_t *const lhs = \
        va_arg(ap, const struct sio_arg_t *const); \
      if (!lhs) return 0; \
 \
      total.bits = lhs->bits; \
      total.sign = lhs->sign; \
      /* Copy over using the largest supported type */ \
      total.v.ull = lhs->v.ull; \
     } \
 \
    while (--args) { \
      const struct sio_arg_t *const rhs = \
        va_arg(ap, const struct sio_arg_t *const); \
      if (!rhs) return 0; \
      /* XXX: test to ensure passing the v.ull works for any type */ \
      if (!safe_##_OP##x(&(total.v.ull), &total, rhs)) \
        return 0; \
    } \
    if (dst) { \
      switch (total.bits) { \
        /* Since the sign doesn't change the storage type - assign directly */ \
        case 8: \
          *((uint8_t *)dst) = total.v.u8; \
          break; \
        case 16: \
          *((uint16_t *)dst) = total.v.u16; \
          break; \
        case 32: \
          *((uint32_t *)dst) = total.v.u32; \
          break; \
        case 64: \
          *((uint64_t *)dst) = total.v.u64; \
          break; \
        default: \
          return 0; \
      } \
    } \
    return 1; \
  }

/*
TODO: Still use the switched sio_s32() maybe?
__sioi(m)(declare_safe_opv)(add)
__sioi(m)(declare_safe_opv)(sub)
__sioi(m)(declare_safe_opv)(mul)
__sioi(m)(declare_safe_opv)(div)
__sioi(m)(declare_safe_opv)(mod)
__sioi(m)(declare_safe_opv)(shl)
__sioi(m)(declare_safe_opv)(shr)
*/

#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_declare_safe_opv



/* Casts B to A if possible. Only call if type_enforce fails. */
/* XXX: Optimize scOk assignment to minimize use */
#if defined(__GNUC__)
#define OPAQUE_SAFE_IOP_PREFIX_MACRO_safe_cast(__DST, __A, __B)  ({ \
  int __sio(var)(__scOk) = 0; \
  if (sizeof(typeof(__A)) == sizeof(typeof(__B))) { \
    /* sign change */ \
    if (!__sio(m)(is_signed)(__A) && !__sio(m)(is_signed)(__B)) { \
        __sio(var)(__scOk) = 1; \
    } else if (__sio(m)(is_signed)(__A) && __sio(m)(is_signed)(__B)) { \
        __sio(var)(__scOk) = 1; \
    } else if (!__sio(m)(is_signed)(__A) && __sio(m)(is_signed)(__B)) { \
      if ((__B) > (typeof(__B))0 || (__B) == (typeof(__B))0) \
        __sio(var)(__scOk) = 1; \
    } else if (__sio(m)(is_signed)(__A) && !__sio(m)(is_signed)(__B)) { \
      /* since they are the same size, the comparison cast should be safe */ \
      if ((__B) < (typeof(__B))__sio(m)(smax)(typeof(__A)) || \
          (__B) == (typeof(__B))__sio(m)(smax)(typeof(__A))) \
        __sio(var)(__scOk) = 1; \
    } \
  } else if (sizeof(typeof(__A)) > sizeof(typeof(__B))) { \
    /* cast up: this allows -1, e.g., which means extension. */ \
    /* Is that _really_ safe ? */ \
    if (!__sio(m)(is_signed)(__A) && !__sio(m)(is_signed)(__B)) { \
        __sio(var)(__scOk) = 1; \
    } else if (__sio(m)(is_signed)(__A) && __sio(m)(is_signed)(__B)) { \
        __sio(var)(__scOk) = 1; \
    } else if (!__sio(m)(is_signed)(__A) && __sio(m)(is_signed)(__B)) { \
      if ((__B) == (typeof(__B))0 || (__B) > (typeof(__B))0) \
        __sio(var)(__scOk) = 1; \
    } else if (__sio(m)(is_signed)(__A) && !__sio(m)(is_signed)(__B)) { \
      /* this is true by default */ \
      if (__sio(m)(smax)(typeof(__A)) >= __sio(m)(umax)(typeof(__B))) \
        __sio(var)(__scOk) = 1; \
      /* This will safely truncate given that smax(a) <= umax(b) */ \
      else if ((__B) < (typeof(__B))__sio(m)(smax)(typeof(__A)) || \
          (__B) == (typeof(__B))__sio(m)(smax)(typeof(__A))) \
        __sio(var)(__scOk) = 1; \
    } \
  } else if (sizeof(typeof(__A)) < sizeof(typeof(__B))) { \
    /* cast down (loss of precision) */ \
    if (!__sio(m)(is_signed)(__A) && !__sio(m)(is_signed)(__B)) { \
      if ((__B) == (typeof(__B))__sio(m)(umax)(typeof(__A))) \
        __sio(var)(__scOk) = 1; \
      if ((__B) < (typeof(__B))__sio(m)(umax)(typeof(__A))) \
        __sio(var)(__scOk) = 1; \
    } else if (__sio(m)(is_signed)(__A) && __sio(m)(is_signed)(__B)) { \
      if (((__B) > (typeof(__B))__sio(m)(smin)(typeof(__A)) || \
           (__B) == (typeof(__B))__sio(m)(smin)(typeof(__A))) && \
          ((__B) < (typeof(__B))__sio(m)(smax)(typeof(__A)) || \
           (__B) == (typeof(__B))__sio(m)(smax)(typeof(__A)))) \
        __sio(var)(__scOk) = 1; \
    } else if (!__sio(m)(is_signed)(__A) && __sio(m)(is_signed)(__B)) { \
      /* this should safely extend */ \
      if (((__B) > (typeof(__B))0 || (__B) == (typeof(__B))0) && \
          (((__B) < (typeof(__B))__sio(m)(umax)(typeof(__A))) || \
           ((__B) == (typeof(__B))__sio(m)(umax)(typeof(__A))))) \
        __sio(var)(__scOk) = 1; \
    } else if (__sio(m)(is_signed)(__A) && !__sio(m)(is_signed)(__B)) { \
      /* this should safely extend */ \
      if ((__B) < (typeof(__B))__sio(m)(smax)(typeof(__A)) || \
          (__B) == (typeof(__B))__sio(m)(smax)(typeof(__A))) \
        __sio(var)(__scOk) = 1; \
    } \
  } \
  __sio(var)(__scOk); \
})
#endif

/* We use a non-void wrapper for assert(). This allows us to factor it away on
 * -DNDEBUG but still have conditionals test the result (and optionally return
 *  false).
 */
/* C99 doesn't seem to allow ({ }) */
#if defined(__GNUC__)
#if defined(NDEBUG)
#  define OPAQUE_SAFE_IOP_PREFIX_MACRO_assert(x) (x)
#else
#  define OPAQUE_SAFE_IOP_PREFIX_MACRO_assert(x) ({ assert(x); 1; })
#endif
#endif


/*** TODO: port all this to new C99 friendly format ***/

/* Primary interface macros */
/* type checking is compiled out if NDEBUG supplied. */
#if defined(__GNUC__)
#if 0 /* going away */
#define safe_add_macro_only(_ptr, __a, __b) \
 ({ int __sio(var)(ok) = 0; \
    typeof(__a) __sio(var)(_a) = (__a), __sio(var)(_b); \
    typeof(_ptr) __sio(var)(p) = (_ptr); \
    if (__sio(m)(type_enforce)(__sio(var)(_a), (__b)) || \
        __sio(m)(assert)(__sio(m)(safe_cast)(__sio(var)(_b), \
                                             __sio(var)(_a), \
                                             (__b)))) { \
      __sio(var)(_b) = (typeof(__a))(__b); \
      if (__sio(m)(is_signed)(__sio(var)(_a))) { \
        __sio(var)(ok) = safe_sadd(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } else { \
        __sio(var)(ok) = safe_uadd(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } \
    } \
    __sio(var)(ok); })
#endif /* going away */

#if 0
#define safe_inc(_pA) ({ \
  typeof(_pA) __sio(var)(pA) = (_pA); \
  safe_add(__sio(var)(pA), *(__sio(var)(pA)), \
           ((typeof(*(__sio(var)(pA))))1)); \
})
#endif

#define safe_add3(_ptr, _A, _B, _C) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_add(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_add((_ptr), __sio(var)(r), __sio(var)(c))); })

#define safe_add4(_ptr, _A, _B, _C, _D) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_A) __sio(var)(r) = 0; \
  (safe_add(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
   safe_add(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
   safe_add((_ptr), __sio(var)(r), (__sio(var)(d)))); })

#define safe_add5(_ptr, _A, _B, _C, _D, _E) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_E) __sio(var)(e) = (_E); \
   typeof(_A) __sio(var)(r) = 0; \
  (safe_add(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
   safe_add(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
   safe_add(&(__sio(var)(r)), __sio(var)(r), __sio(var)(d)) && \
   safe_add((_ptr), __sio(var)(r), __sio(var)(e))); })

#if 0
#define safe_sub_macro_only(_ptr, __a, __b) \
 ({ int __sio(var)(ok) = 0; \
    typeof(__a) __sio(var)(_a) = (__a); \
    typeof(__b) __sio(var)(_b) = (__b); \
    typeof(_ptr) __sio(var)(p) = (_ptr); \
    if (__sio(m)(type_enforce)(__sio(var)(_a), (__b)) || \
        __sio(m)(assert)(__sio(m)(safe_cast)(__sio(var)(_b), \
                                             __sio(var)(_a), \
                                             (__b)))) { \
      __sio(var)(_b) = (typeof(__a))(__b); \
      if (__sio(m)(is_signed)(__sio(var)(_a))) { \
        __sio(var)(ok) = safe_ssub(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } else { \
        __sio(var)(ok) = safe_usub(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } \
    } \
    __sio(var)(ok); })
#endif

#if 0
#define safe_dec(_pA) ({ \
  typeof(_pA) __sio(var)(pA) = (_pA); \
  safe_sub(__sio(var)(pA), *__sio(var)(pA), \
           ((typeof(*(__sio(var)(pA))))1)); \
})
#endif
/* These are sequentially performed */
#define safe_sub3(_ptr, _A, _B, _C) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_sub(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_sub((_ptr), __sio(var)(r), __sio(var)(c))); })

#define safe_sub4(_ptr, _A, _B, _C, _D) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_A) __sio(var)(r) = 0; \
  (safe_sub(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
   safe_sub(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
   safe_sub((_ptr), __sio(var)(r), (__sio(var)(d)))); })

#define safe_sub5(_ptr, _A, _B, _C, _D, _E) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_E) __sio(var)(e) = (_E); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_sub(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_sub(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
    safe_sub(&(__sio(var)(r)), __sio(var)(r), __sio(var)(d)) && \
    safe_sub((_ptr), __sio(var)(r), __sio(var)(e))); })


 
#define safe_mul_macro_only(_ptr, __a, __b) \
 ({ int __sio(var)(ok) = 0; \
    typeof(__a) __sio(var)(_a) = (__a); \
    typeof(__b) __sio(var)(_b) = (__b); \
    typeof(_ptr) __sio(var)(p) = (_ptr); \
    if (__sio(m)(type_enforce)(__sio(var)(_a), (__b)) || \
        __sio(m)(assert)(__sio(m)(safe_cast)(__sio(var)(_b), \
                                             __sio(var)(_a), \
                                             (__b)))) { \
      __sio(var)(_b) = (typeof(__a))(__b); \
      if (__sio(m)(is_signed)(__sio(var)(_a))) { \
        __sio(var)(ok) = safe_smul(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } else { \
        __sio(var)(ok) = safe_umul(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } \
    } \
    __sio(var)(ok); })

#define safe_mul3(_ptr, _A, _B, _C) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_mul(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_mul((_ptr), __sio(var)(r), __sio(var)(c))); })

#define safe_mul4(_ptr, _A, _B, _C, _D) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_A) __sio(var)(r) = 0; \
  (safe_mul(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
   safe_mul(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
   safe_mul((_ptr), __sio(var)(r), (__sio(var)(d)))); })

#define safe_mul5(_ptr, _A, _B, _C, _D, _E) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_E) __sio(var)(e) = (_E); \
   typeof(_A) __sio(var)(r) = 0; \
  (safe_mul(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
   safe_mul(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
   safe_mul(&(__sio(var)(r)), __sio(var)(r), __sio(var)(d)) && \
   safe_mul((_ptr), __sio(var)(r), __sio(var)(e))); })

#define safe_div_macro_only(_ptr, __a, __b) \
 ({ int __sio(var)(ok) = 0; \
    typeof(__a) __sio(var)(_a) = (__a); \
    typeof(__b) __sio(var)(_b) = (__b); \
    typeof(_ptr) __sio(var)(p) = (_ptr); \
    if (__sio(m)(type_enforce)(__sio(var)(_a), (__b)) || \
        __sio(m)(assert)(__sio(m)(safe_cast)(__sio(var)(_b), \
                                             __sio(var)(_a), \
                                             (__b)))) { \
      __sio(var)(_b) = (typeof(__a))(__b); \
      if (__sio(m)(is_signed)(__sio(var)(_a))) { \
        __sio(var)(ok) = safe_sdiv(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } else { \
        __sio(var)(ok) = safe_udiv(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } \
    } \
    __sio(var)(ok); })

#define safe_div3(_ptr, _A, _B, _C) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_div(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_div((_ptr), __sio(var)(r), __sio(var)(c))); })

#define safe_div4(_ptr, _A, _B, _C, _D) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_A) __sio(var)(r) = 0; \
  (safe_div(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
   safe_div(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
   safe_div((_ptr), __sio(var)(r), (__sio(var)(d)))); })

#define safe_div5(_ptr, _A, _B, _C, _D, _E) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_E) __sio(var)(e) = (_E); \
   typeof(_A) __sio(var)(r) = 0; \
  (safe_div(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
   safe_div(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
   safe_div(&(__sio(var)(r)), __sio(var)(r), __sio(var)(d)) && \
   safe_div((_ptr), __sio(var)(r), __sio(var)(e))); })

#define safe_mod_macro_only(_ptr, __a, __b) \
 ({ int __sio(var)(ok) = 0; \
    typeof(__a) __sio(var)(_a) = (__a); \
    typeof(__b) __sio(var)(_b) = (__b); \
    typeof(_ptr) __sio(var)(p) = (_ptr); \
    if (__sio(m)(type_enforce)(__sio(var)(_a), (__b)) || \
        __sio(m)(assert)(__sio(m)(safe_cast)(__sio(var)(_b), \
                                             __sio(var)(_a), \
                                             (__b)))) { \
      __sio(var)(_b) = (typeof(__a))(__b); \
      if (__sio(m)(is_signed)(__sio(var)(_a))) { \
        __sio(var)(ok) = safe_smod(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } else { \
        __sio(var)(ok) = safe_umod(__sio(var)(p), \
                                   __sio(var)(_a), \
                                   __sio(var)(_b)); \
      } \
    } \
    __sio(var)(ok); })

#define safe_mod3(_ptr, _A, _B, _C) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_mod(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_mod((_ptr), __sio(var)(r), __sio(var)(c))); })

#define safe_mod4(_ptr, _A, _B, _C, _D) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_mod(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_mod(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
    safe_mod((_ptr), __sio(var)(r), (__sio(var)(d)))); })

#define safe_mod5(_ptr, _A, _B, _C, _D, _E) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C), \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_E) __sio(var)(e) = (_E); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_mod(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_mod(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
    safe_mod(&(__sio(var)(r)), __sio(var)(r), __sio(var)(d)) && \
    safe_mod((_ptr), __sio(var)(r), __sio(var)(e))); })

/* XXX: does it matter if __a and __b are the same type?
 *      signedness is useful to have incommon.
 */
#define safe_shl_macro_only(_ptr, __a, __b) \
 ({ int __sio(var)(ok) = 0; \
    typeof(__a) __sio(var)(_a) = (__a), __sio(var)(_b); \
    typeof(_ptr) __sio(var)(p) = (_ptr); \
    if (__sio(m)(type_enforce)(__sio(var)(_a), (__b)) || \
        __sio(m)(assert)(__sio(m)(safe_cast)(__sio(var)(_b), \
                                             __sio(var)(_a), \
                                             (__b)))) { \
      __sio(var)(_b) = (typeof(__a))(__b); \
      if (__sio(m)(is_signed)(__sio(var)(_a))) { \
        __sio(var)(ok) = safe_sshl(__sio(var)(p), \
                                      __sio(var)(_a), \
                                      __sio(var)(_b)); \
      } else { \
        __sio(var)(ok) = safe_ushl(__sio(var)(p), \
                                     __sio(var)(_a), \
                                     __sio(var)(_b)); \
      } \
    } \
    __sio(var)(ok); })

#define safe_shr_macro_only(_ptr, __a, __b) \
 ({ int __sio(var)(ok) = 0; \
    typeof(__a) __sio(var)(_a) = (__a), __sio(var)(_b); \
    typeof(_ptr) __sio(var)(p) = (_ptr); \
    if (__sio(m)(type_enforce)(__sio(var)(_a), (__b)) || \
        __sio(m)(assert)(__sio(m)(safe_cast)(__sio(var)(_b), \
                                             __sio(var)(_a), \
                                             (__b)))) { \
      __sio(var)(_b) = (typeof(__a))(__b); \
      if (__sio(m)(is_signed)(__sio(var)(_a))) { \
        __sio(var)(ok) = safe_sshr(__sio(var)(p), \
                                      __sio(var)(_a), \
                                      __sio(var)(_b)); \
      } else { \
        __sio(var)(ok) = safe_ushr(__sio(var)(p), \
                                     __sio(var)(_a), \
                                     __sio(var)(_b)); \
      } \
    } \
    __sio(var)(ok); })




/*** Safe integer operation implementation macros ***/


#endif
/* safe_iopf
 *
 * Takes in a character array which specifies the operations
 * to perform on a given value. The value will be assumed to be
 * of the type specified for each operation.
 *
 * Currently accepted format syntax is:
 *   [type_marker]operation...
 * The type marker may be any of the following:
 * - s[8,16,32,64] for signed of size 8-bit, etc
 * - u[8,16,32,64] for unsigned of size 8-bit, etc
 * If no type_marker is specified, it is assumed to be s32.
 * If a left-hand side type-marker is given, then that will
 * become the default for all remaining operands.
 * E.g.,
 *   safe_iopf(&dst, "u16**+", a, b, c. d);
 * is equivalent to ((a*b)*c)+d all of type u16.
 * This function uses FIFO and not any other order of operations/precedence.
 *
 * The operation must be one of the following:
 * - * -- multiplication
 * - / -- division
 * - - -- subtraction
 * - + -- addition
 * - % -- modulo (remainder)
 * 
 * Whitespace will be ignored.
 *
 * Args:
 * - pointer to the final result
 * - array of format characters
 * - all remaining arguments are derived from the format
 * Output:
 * - Returns 1 on success leaving the result in value
 * - Returns 0 on failure leaving the contents of value *unknown*
 */

/* TODO: make safe_iopf use the sio_<type> markup.  This means
 * the format can be typeless. E.g,
 *   safe_iopf(res, "++/+<<1", _s32(a), _u16(c), _u64(100), ...);
 */
int safe_iopf(void *result, const char *const fmt, ...);

#undef sio_inline

#endif  /* _SAFE_IOP_H */
