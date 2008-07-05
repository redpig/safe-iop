/* safe_iop
 * License:: BSD
 * Author:: Will Drewry <redpig@dataspill.org>
 * 
 * To Do:
 * - Clean up TODOs
 * - Clean out legacy code and fix up style (line len, etc)
 * - Get PCC working
 * - Test out with other compilers
 * - Add tests for typeof() specific notes
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
  ((__sio(m)(is_signed)(__A) == OPAQUE_SAFE_IOP_PREFIX_MACRO_is_signed(__B)) && \
   (sizeof(typeof(__A)) == sizeof(typeof(__B))))
#endif


/* This structure is used to pass the arguments to the safe integer operations.
 * Because there is no 'typeof' function in C99, many compilers do not support
 * this extension.  Without it, we have to approximate the same functionality.
 * When not using GCC, we assume no typeof() support. This means that you must
 * use type-wrapping macros:
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
     /* holders only -- these will be accessed via the above holders if possible */
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
#define sio_s8(_a) (&(struct sio_arg_t){ .bits = 8, .sign = 1, .v.s8 = _a })
#define sio_u8(_a) (&(struct sio_arg_t){ .bits = 8, .sign = 0, .v.u8 = _a })
#define sio_s16(_a) (&(struct sio_arg_t){ .bits = 16, .sign = 1, .v.s16 = _a })
#define sio_u16(_a) (&(struct sio_arg_t){ .bits = 16, .sign = 0, .v.u16 = _a })
#define sio_s32(_a) (&(struct sio_arg_t){ .bits = 32, .sign = 1, .v.s32 = _a })
#define sio_u32(_a) (&(struct sio_arg_t){ .bits = 32, .sign = 0, .v.u32 = _a })
#define sio_s64(_a) (&(struct sio_arg_t){ .bits = 64, .sign = 1, .v.s64 = _a })
#define sio_u64(_a) (&(struct sio_arg_t){ .bits = 64, .sign = 0, .v.u64 = _a })

/* Types with varying sizes which should be access by <s|u><bits> */
#define sio_l(_a) (&(struct sio_arg_t){ .bits = sizeof(signed long)*CHAR_BIT, .sign = 1, .v.l = _a })
#define sio_ul(_a) (&(struct sio_arg_t){ .bits = sizeof(unsigned long)*CHAR_BIT, .sign = 0, .v.ul = _a })
#define sio_ll(_a) (&(struct sio_arg_t){ .bits = sizeof(signed long long)*CHAR_BIT, .sign = 1, .v.ll = _a })
#define sio_ull(_a) (&(struct sio_arg_t){ .bits = sizeof(unsigned long long)*CHAR_BIT, .sign = 0, .v.ull = _a })
#define sio_szt(_a) (&(struct sio_arg_t){ .bits = sizeof(size_t)*CHAR_BIT, .sign = 0, .v.szt = _a })
#define sio_sszt(_a) (&(struct sio_arg_t){ .bits = sizeof(ssize_t)*CHAR_BIT, .sign = 1, .v.sszt = _a })
#define sio_i(_a) (&(struct sio_arg_t){ .bits = sizeof(int)*CHAR_BIT, .sign = 1, .v.i = _a })
#define sio_ui(_a) (&(struct sio_arg_t){ .bits = sizeof(unsigned int)*CHAR_BIT, .sign = 0, .v.ui = _a })

#ifdef __GNUC__
 /* Slowly guard all GCC specific functionality with __GNUC__ tests
  * but otherwise this should all be C99 friendly.
  */
#define safe_add(_dst, _a, _b) ({ \
  typeof(_a) __sio(var)(add_a) = (_a); \
  typeof(_b) __sio(var)(add_b) = (_b); \
  _Bool __sio(var)(ok) = 1; \
  struct sio_arg_t __sio(var)(a) = {0}, __sio(var)(b) = {0}; \
  __sio(var)(a).bits = sizeof(typeof(__sio(var)(add_a)))*CHAR_BIT; \
  __sio(var)(b).bits = sizeof(typeof(__sio(var)(add_b)))*CHAR_BIT; \
  __sio(var)(a).sign = __sio(m)(is_signed)(__sio(var)(add_a)); \
  __sio(var)(b).sign = __sio(m)(is_signed)(__sio(var)(add_b)); \
  switch (__sio(var)(a).bits) { \
    case 8: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s8 = __sio(var)(add_a); \
      else                    __sio(var)(a).v.u8 = __sio(var)(add_a); \
      break; \
    case 16: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s16 = __sio(var)(add_a); \
      else                    __sio(var)(a).v.u16 = __sio(var)(add_a); \
      break; \
    case 32: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s32 = __sio(var)(add_a); \
      else                    __sio(var)(a).v.u32 = __sio(var)(add_a); \
      break; \
    case 64: \
      if (__sio(var)(a).sign) __sio(var)(a).v.s64 = __sio(var)(add_a); \
      else                    __sio(var)(a).v.u64 = __sio(var)(add_a); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  switch (__sio(var)(b).bits) { \
    case 8: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s8 = __sio(var)(add_b); \
      else                    __sio(var)(b).v.u8 = __sio(var)(add_b); \
      break; \
    case 16: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s16 = __sio(var)(add_b); \
      else                    __sio(var)(b).v.u16 = __sio(var)(add_b); \
      break; \
    case 32: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s32 = __sio(var)(add_b); \
      else                    __sio(var)(b).v.u32 = __sio(var)(add_b); \
      break; \
    case 64: \
      if (__sio(var)(b).sign) __sio(var)(b).v.s64 = __sio(var)(add_b); \
      else                    __sio(var)(b).v.u64 = __sio(var)(add_b); \
      break; \
    default: \
      __sio(var)(ok) = 0; \
  } \
  if (__sio(var)(ok))  \
    __sio(var)(ok) = safe_addx(_dst,  &__sio(var)(a), &__sio(var)(b)); \
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

/*** Helpers for duplicating code easily in safe_cast ***/
#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_same_tos(_bits, _type) \
  case _bits: { \
    if (rhs->v.u##_bits > __sio(m)(smax)(u##_type)) \
      return 0; \
    *cast = *sio_s##_bits(((_type)rhs->v.u##_bits)); \
    return 1; \
   } break;


#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_case_same_tou(_bits, _type) \
  case _bits: { \
    if (rhs->v.s##_bits < 0) \
      return 0; \
    *cast = *sio_u##_bits((_type)rhs->v.u##_bits); \
    return 1; \
   } break;

/* Casting up cases */
#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_up_signed(_bits) \
    case _bits: { \
      switch (lhs->bits) { \
       /* 8 is currently the smallest so this should never be reached */ \
        case 8: \
         *cast = *sio_s8((int8_t)rhs->v.s##_bits); \
          break; \
        case 16: \
          *cast = *sio_s16((int16_t)rhs->v.s##_bits); \
          break; \
        case 32: \
          *cast = *sio_s32((int32_t)rhs->v.s##_bits); \
          break; \
        case 64: \
          *cast = *sio_s64((int64_t)rhs->v.s##_bits); \
          break; \
        default: \
          return 0; \
      } \
      return 1; \
    } break;


#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_up_unsigned(_bits) \
    case _bits: { \
      switch (lhs->bits) { \
       /* 8 is currently the smallest so this should never be reached */ \
        case 8: \
          *cast = *sio_u8((uint8_t)rhs->v.u##_bits); \
          break; \
        case 16: \
          *cast = *sio_u16((uint16_t)rhs->v.u##_bits); \
          break; \
        case 32: \
          *cast = *sio_u32((uint32_t)rhs->v.u##_bits); \
          break; \
        case 64: \
          *cast = *sio_u64((uint64_t)rhs->v.u##_bits); \
          break; \
        default: \
          return 0; \
      } \
      return 1; \
    } break;

#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_up_tos(_bits) \
    case _bits: { \
      switch (lhs->bits) { \
        /* This is unreachable unless smaller types are added */ \
        case 8: \
          if (rhs->v.u##_bits > __sio(m)(smax)(uint8_t)) \
            return 0; \
          *cast = *sio_s8((int8_t)rhs->v.u##_bits); \
          break; \
        case 16: \
          /* SAFE: GCC warns on this before 4.3 (-Wno-type-limits) */ \
          if (rhs->v.u##_bits > __sio(m)(smax)(uint16_t)) \
            return 0; \
          *cast = *sio_s16((int16_t)rhs->v.u##_bits); \
          break; \
        case 32: \
          if (rhs->v.u##_bits > __sio(m)(smax)(uint32_t)) \
            return 0; \
          *cast = *sio_s32((int32_t)rhs->v.u##_bits); \
          break; \
        case 64: \
          if (rhs->v.u##_bits > __sio(m)(smax)(uint64_t)) \
            return 0; \
          *cast = *sio_s64((int64_t)rhs->v.u##_bits); \
          break; \
        default: \
          return 0; \
      } \
      return 1; \
    } break;

#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_up_tou(_bits) \
    case _bits: { \
      switch (lhs->bits) { \
        /* This is unreachable unless we add smaller types */ \
        case 8: \
          if (rhs->v.s##_bits < 0) \
            return 0; \
          *cast = *sio_u8((uint8_t)rhs->v.s##_bits); \
          break; \
        /* rhs should always be smaller than umax(lhs) so we only check \
         * for negative  \
         */ \
        case 16: \
          if (rhs->v.s##_bits < 0) \
            return 0; \
          *cast = *sio_u16((uint16_t)rhs->v.s##_bits); \
          break; \
        case 32: \
          if (rhs->v.s##_bits < 0) \
            return 0; \
          *cast = *sio_u32((uint32_t)rhs->v.s##_bits); \
          break; \
        case 64: \
          if (rhs->v.s##_bits < 0) \
            return 0; \
          *cast = *sio_u64((uint64_t)rhs->v.s##_bits); \
          break; \
        default: \
          return 0; \
      } \
      return 1; \
    } break;


/* Casting down cases */
#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_down_signed(_bits) \
    case _bits: { \
      switch (lhs->bits) { \
        case 8: \
         if (rhs->v.s##_bits < __sio(m)(smin)(int8_t) || \
             rhs->v.s##_bits > __sio(m)(smax)(int8_t)) \
           return 0; \
         *cast = *sio_s8((int8_t)rhs->v.s##_bits); \
          break; \
        case 16: \
         if (rhs->v.s##_bits < __sio(m)(smin)(int16_t) || \
             rhs->v.s##_bits > __sio(m)(smax)(int16_t)) \
           return 0; \
          *cast = *sio_s16((int16_t)rhs->v.s##_bits); \
          break; \
        case 32: \
         if (rhs->v.s##_bits < __sio(m)(smin)(int32_t) || \
             rhs->v.s##_bits > __sio(m)(smax)(int32_t)) \
           return 0; \
          *cast = *sio_s32((int32_t)rhs->v.s##_bits); \
          break; \
        case 64: \
          /* this is unreachable unless we add a larger possible size */ \
         if (rhs->v.s##_bits < __sio(m)(smin)(int64_t) || \
             rhs->v.s##_bits > __sio(m)(smax)(int64_t)) \
           return 0; \
          *cast = *sio_s64((int64_t)rhs->v.s##_bits); \
          break; \
        default: \
          return 0; \
      } \
      return 1; \
    } break;


#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_down_unsigned(_bits) \
    case _bits: { \
      switch (lhs->bits) { \
        case 8: \
          if (rhs->v.u##_bits > __sio(m)(umax)(uint8_t)) \
            return 0; \
          *cast = *sio_u8((uint8_t)rhs->v.u##_bits); \
          break; \
        case 16: \
          if (rhs->v.u##_bits > __sio(m)(umax)(uint16_t)) \
            return 0; \
          *cast = *sio_u16((uint16_t)rhs->v.u##_bits); \
          break; \
        case 32: \
          if (rhs->v.u##_bits > __sio(m)(umax)(uint32_t)) \
            return 0; \
          *cast = *sio_u32((uint32_t)rhs->v.u##_bits); \
          break; \
        case 64: \
          /* this is unreachable unless we add a larger possible size */ \
          if (rhs->v.u##_bits > __sio(m)(umax)(uint64_t)) \
            return 0; \
          *cast = *sio_u64((uint64_t)rhs->v.u##_bits); \
          break; \
        default: \
          return 0; \
      } \
      return 1; \
    } break;

#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_down_tos(_bits) \
    case _bits: { \
      switch (lhs->bits) { \
        case 8: \
          /* SAFE: GCC warns on this before 4.3 (-Wno-type-limits) */ \
          if (rhs->v.u##_bits > __sio(m)(smax)(uint8_t)) \
            return 0; \
          *cast = *sio_s8((int8_t)rhs->v.u##_bits); \
          break; \
        case 16: \
          if (rhs->v.u##_bits > __sio(m)(smax)(uint16_t)) \
            return 0; \
          *cast = *sio_s16((int16_t)rhs->v.u##_bits); \
          break; \
        case 32: \
          if (rhs->v.u##_bits > __sio(m)(smax)(uint32_t)) \
            return 0; \
          *cast = *sio_s32((int32_t)rhs->v.u##_bits); \
          break; \
        case 64: \
          if (rhs->v.u##_bits > __sio(m)(smax)(uint64_t)) \
            return 0; \
          *cast = *sio_s64((int64_t)rhs->v.u##_bits); \
          break; \
        default: \
          return 0; \
      } \
      return 1; \
    } break;

#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_down_tou(_bits) \
    case _bits: { \
      switch (lhs->bits) { \
        case 8: \
          /* XXX: will the comparator correctly promote for safe testing? */ \
          if (rhs->v.s##_bits < 0 || \
              rhs->v.s##_bits > __sio(m)(umax)(uint8_t)) \
            return 0; \
          *cast = *sio_u8((uint8_t)rhs->v.s##_bits); \
          break; \
        case 16: \
          if (rhs->v.s##_bits < 0 || \
              rhs->v.s##_bits > __sio(m)(umax)(uint16_t)) \
            return 0; \
          *cast = *sio_u16((uint16_t)rhs->v.s##_bits); \
          break; \
        case 32: \
          if (rhs->v.s##_bits < 0 || \
              rhs->v.s##_bits > __sio(m)(umax)(uint32_t)) \
            return 0; \
          *cast = *sio_u32((uint32_t)rhs->v.s##_bits); \
          break; \
        case 64: \
          if (rhs->v.s##_bits < 0 || \
              rhs->v.s##_bits > __sio(m)(umax)(uint64_t)) \
            return 0; \
          *cast = *sio_u64((uint64_t)rhs->v.s##_bits); \
          break; \
        default: \
          return 0; \
      } \
      return 1; \
    } break;


static inline _Bool __sio(f)(safe_cast)(struct sio_arg_t *cast,
                                        const struct sio_arg_t *const lhs,
                                        const struct sio_arg_t *const rhs) {
  if (cast == NULL) return 0;
  /* same bit count */
  if (lhs->bits == rhs->bits) { /* sign change */
    if (lhs->sign == rhs->sign) {
      /* Same width and sign. we're good. */
      /* XXX: can we do this cleanly without the copy? */
      *cast = *rhs;
      return 1;
    } else if (lhs->sign && !rhs->sign) {
      switch (rhs->bits) {
        /* rhs must be able to be contained within the signed size max */
        __sioi(m)(safe_cast_same_tos)(8, int8_t)
        __sioi(m)(safe_cast_same_tos)(16, int16_t)
        __sioi(m)(safe_cast_same_tos)(32, int32_t)
        __sioi(m)(safe_cast_same_tos)(64, int64_t)
        default:
          return 0;
      }
    } else {
      switch (rhs->bits) {
        /* rhs must be able to be contained within the signed size max */
        __sioi(m)(safe_cast_case_same_tou)(8, uint8_t)
        __sioi(m)(safe_cast_case_same_tou)(16, uint16_t)
        __sioi(m)(safe_cast_case_same_tou)(32, uint32_t)
        __sioi(m)(safe_cast_case_same_tou)(64, uint64_t)
        default:
          return 0;
      }
    }
  } else if (lhs->bits > rhs->bits) {  /* cast up */
    if (lhs->sign && rhs->sign) {
      switch (rhs->bits) {
        __sioi(m)(safe_cast_up_signed)(8)
        __sioi(m)(safe_cast_up_signed)(16)
        __sioi(m)(safe_cast_up_signed)(32)
        /* Cannot cast up from largest type */
        /* __sioi(m)(safe_cast_up_signed)(64) */
        default:
          return 0;
      }
    } else if (!lhs->sign && !rhs->sign) {
      switch (rhs->bits) {
        __sioi(m)(safe_cast_up_unsigned)(8)
        __sioi(m)(safe_cast_up_unsigned)(16)
        __sioi(m)(safe_cast_up_unsigned)(32)
        /* Cannot cast up from largest type */
        /* __sioi(m)(safe_cast_up_unsigned)(64) */
        default:
          return 0;
      }
    } else if (lhs->sign && !rhs->sign) {
      switch (rhs->bits) {
        __sioi(m)(safe_cast_up_tos)(8)
        __sioi(m)(safe_cast_up_tos)(16)
        __sioi(m)(safe_cast_up_tos)(32)
        /* Cannot cast up from largest type */
        /* __sioi(m)(safe_cast_up_tos)(64) */
        default:
          return 0;
      }
    } else if (!lhs->sign && rhs->sign) {
      switch (rhs->bits) {
        __sioi(m)(safe_cast_up_tou)(8)
        __sioi(m)(safe_cast_up_tou)(16)
        __sioi(m)(safe_cast_up_tou)(32)
        /* Cannot cast up from largest type */
        /* __sioi(m)(safe_cast_up_tou)(64) */
        default:
          return 0;
      }
    }
  } else { /* cast down */
    if (!lhs->sign && !rhs->sign) {
      switch (rhs->bits) {
        /* rhs must be greater than 8 to cast down unless
         * smaller types are added */
        /* __sioi(m)(safe_cast_down_unsigned)(8) */
        __sioi(m)(safe_cast_down_unsigned)(16)
        __sioi(m)(safe_cast_down_unsigned)(32)
        __sioi(m)(safe_cast_down_unsigned)(64)
        default:
          return 0;
      }
    } else if (lhs->sign && rhs->sign) {
      switch (rhs->bits) {
        /* rhs must be greater than 8 to cast down unless
         * smaller types are added */
        /* __sioi(m)(safe_cast_down_signed)(8) */
        __sioi(m)(safe_cast_down_signed)(16)
        __sioi(m)(safe_cast_down_signed)(32)
        __sioi(m)(safe_cast_down_signed)(64)
        default:
          return 0;
      }
    } else if (!lhs->sign && rhs->sign) {
      switch (rhs->bits) {
        /* Can't cast down from the smallest size. */
        /* __sioi(m)(safe_cast_down_tou)(8) */
        __sioi(m)(safe_cast_down_tou)(16)
        __sioi(m)(safe_cast_down_tou)(32)
        __sioi(m)(safe_cast_down_tou)(64)
        default:
          return 0;
      }
    } else { /* (lhs->sign && !rhs->sign) */
      switch (rhs->bits) {
        /* Can't cast down from the smallest size. */
        /* __sioi(m)(safe_cast_down_tos)(8) */
        __sioi(m)(safe_cast_down_tos)(16)
        __sioi(m)(safe_cast_down_tos)(32)
        __sioi(m)(safe_cast_down_tos)(64)
        default:
          return 0;
      }
    }
  } /* end cast down */
  return 1;
}
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_down_tos
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_down_tou
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_down_signed
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_down_unsigned
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_up_tos
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_up_tou
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_up_signed
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_up_unsigned
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_case_same_tou
#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_safe_cast_case_same_tos


/*** Same-type addition macros ***/
#define safe_uadd(_ok, _type, _ptr, _a, _b) { \
  if ((_type)(_b) <= (_type)(__sio(m)(umax)(_type) - (_a))) { \
    if ((_ptr)) { *((_type *)(_ptr)) = (_a) + (_b); } \
    (_ok) = 1; \
  } else { \
    (_ok) = 0; \
  } \
}

#define safe_sadd(_ok, _type, _ptr, _a, _b) { \
  if (((_b) > (_type)0) && ((_a) > (_type)0)) { /*>0*/ \
    if ((_a) > (_type)(__sio(m)(smax)(_type) - (_b))) (_ok) = 0; \
    else (_ok) = 1; \
  } else if (!((_b) > (_type)0) && !((_a) > (_type)0)) { /*<0*/ \
    if ((_a) < (_type)(__sio(m)(smin)(_type) - (_b))) (_ok) = 0; \
    else (_ok) = 1; \
  } else { \
    (_ok) = 1; \
  } \
  if ((_ok) && (_ptr)) { *((_type*)(_ptr)) = (_a) + (_b); } \
}

/*** Same-type subtraction macros ***/
#define safe_usub(_ok, _type, _ptr, _a, _b) { \
  if ((_a) >= (_b)) { \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) - (_b); } \
    (_ok) = 1; \
  } else { \
    (_ok) = 0; \
  } \
}

#define safe_ssub(_ok, _type, _ptr, _a, _b) { \
  if (!((_b) <= 0 && (_a) > (__sio(m)(smax)(_type) + (_b))) && \
      !((_b) > 0 && (_a) < (__sio(m)(smin)(_type) + (_b)))) { \
      (_ok) = 1; \
      if ((_ptr)) { *((_type*)(_ptr)) = (_a) - (_b); } \
  } else { \
    (_ok) = 0; \
  } \
}


/*** Same-type multiplication macros ***/
#define safe_umul(_ok, _type, _ptr, _a, _b) { \
  if (!(_b) || (_a) <= (__sio(m)(umax)(_type) / (_b))) { \
     (_ok) = 1; \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) * (_b); } \
  } else { \
    (_ok) = 0; \
  } \
}

#define safe_smul(_ok, _type, _ptr, _a, _b) { \
  (_ok) = 1; /* clean this up later */ \
  if ((_a) > 0) {  /* a is positive */ \
    if ((_b) > 0) {  /* b and a are positive */ \
      if ((_a) > (__sio(m)(smax)(_type) / (_b))) { \
        (_ok) = 0; \
      } \
    } else { /* a positive, b non-positive */ \
      if ((_b) < (__sio(m)(smin)(_type) / (_a))) { \
        (_ok) = 0; \
      } \
    } /* a positive, b non-positive */ \
  } else { /* a is non-positive */ \
    if ((_b) > 0) { /* a is non-positive, b is positive */ \
      if ((_a) < (__sio(m)(smin)(_type) / (_b))) { \
      (_ok) = 0; \
      } \
    } else { /* a and b are non-positive */ \
      if( ((_a) != 0) && ((_b) < (__sio(m)(smax)(_type) / (_a)))) { \
        (_ok) = 0; \
      } \
    } /* end if a and b are non-positive */ \
  } /* end if a is non-positive */ \
  if ((_ok) && (_ptr)) { *((_type*)(_ptr)) = (_a) * (_b); } \
}

/*** Same-type division macros ***/

/* div-by-zero is the only thing addressed */
#define safe_udiv(_ok, _type, _ptr, _a, _b) { \
  if ((_b) != 0) { \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) / (_b); } \
    (_ok) = 1; \
  } else { \
    (_ok) = 0; \
  } \
}

/* Addreses div by zero and smin -1 */
#define safe_sdiv(_ok, _type, _ptr, _a, _b) { \
  if ((_b) != 0 && \
      (((_a) != __sio(m)(smin)(_type)) || ((_b) != (_type)-1))) { \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) / (_b); } \
    (_ok) = 1; \
  } else { \
    (_ok) = 0; \
  } \
}


/*** Same-type modulo macros ***/
#define safe_umod(_ok, _type, _ptr, _a, _b) { \
  if ((_b) != 0) { \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) % (_b); } \
    (_ok) = 1; \
  } else { \
    (_ok) = 0; \
  } \
}

/* Addreses mod by zero and smin -1 */
#define safe_smod(_ok, _type, _ptr, _a, _b) { \
  if ((_b) != 0 && \
      (((_a) != __sio(m)(smin)(_type)) || ((_b) != (_type)-1))) { \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) % (_b); } \
    (_ok) = 1; \
  } else { \
    (_ok) = 0; \
  } \
}

/*** Same-type left-shift macros ***/
#define safe_sshl(_ok, _type, _ptr, _a, _b) { \
  if (((_a) < 0) || \
      ((_b) < 0) || \
      ((_b) >= sizeof(_type)*CHAR_BIT) || \
      ((_a) > (__sio(m)(smax)(_type) >> (_b)))) { \
    (_ok) = 0; \
  } else { \
    (_ok) = 1; \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) << (_b); } \
  } \
}

#define safe_ushl(_ok, _type, _ptr, _a, _b) { \
  if (((_b) >= sizeof(_type)*CHAR_BIT) || \
      ((_a) > (__sio(m)(umax)(_type) >> (_b)))) { \
    (_ok) = 0; \
  } else { \
    (_ok) = 1; \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) << (_b); } \
  } \
}

/*** Same-type right-shift macros ***/
/* XXX: CERT doesnt recommend failing on -a, but it is undefined */
#define safe_sshr(_ok, _type, _ptr, _a, _b) { \
  if (!((_a) > 0 || (_a) == 0) || \
      !((_b) > 0 || (_b) == 0) || \
      ((_b) >= sizeof(_type)*CHAR_BIT)) { \
    (_ok) = 0; \
  } else { \
    (_ok) = 1; \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) >> (_b); } \
  } \
}

/* this doesn't whine if 0 >> n. */
#define safe_ushr(_ok, _type, _ptr, _a, _b) { \
  if ((_b) >= (sizeof(_type)*CHAR_BIT)) { \
    (_ok) = 0; \
  } else { \
    (_ok) = 1; \
    if ((_ptr)) { *((_type*)(_ptr)) = (_a) >> (_b); } \
  } \
}

/*** Actual interface declarations ***/
#define safe_inc(_type, _p) safe_addx(_p, sio_##_type(*_p), sio_##_type(1))
#define safe_dec(_type, _p) safe_subx(_p, sio_##_type(*_p), sio_##_type(1))

#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_declare_safe_op(_OP) \
  static inline _Bool safe_##_OP##x(void *dst, \
                                const struct sio_arg_t *const a, \
                                const struct sio_arg_t *const b) { \
    _Bool ok = 0; \
    struct sio_arg_t rhs; \
    /* Ensure cast down for b works or fail here */ \
    if (!__sio(f)(safe_cast)(&rhs, a, b)) \
      return 0; \
   \
    if (a->sign) { \
      switch (a->bits) { \
        case 8: safe_s##_OP(ok, int8_t, dst, a->v.s8, rhs.v.s8); break; \
        case 16: safe_s##_OP(ok, int16_t, dst, a->v.s16, rhs.v.s16); break; \
        case 32: safe_s##_OP(ok, int32_t, dst, a->v.s32, rhs.v.s32); break; \
        case 64: safe_s##_OP(ok, int64_t, dst, a->v.s64, rhs.v.s64); break; \
      } \
    } else { \
      switch (a->bits) { \
        case 8: safe_u##_OP(ok, uint8_t, dst, a->v.u8, rhs.v.u8); break; \
        case 16: safe_u##_OP(ok, uint16_t, dst, a->v.u16, rhs.v.u16); break; \
        case 32: safe_u##_OP(ok, uint32_t, dst, a->v.u32, rhs.v.u32); break; \
        case 64: safe_u##_OP(ok, uint64_t, dst, a->v.u64, rhs.v.u64); break; \
      } \
    } \
    return ok; \
  }

__sioi(m)(declare_safe_op)(add)
__sioi(m)(declare_safe_op)(sub)
__sioi(m)(declare_safe_op)(mul)
__sioi(m)(declare_safe_op)(div)
__sioi(m)(declare_safe_op)(mod)
__sioi(m)(declare_safe_op)(shl)
__sioi(m)(declare_safe_op)(shr)

#undef OPAQUE_SAFE_IOP_PREFIXI_MACRO_declare_safe_op


#define OPAQUE_SAFE_IOP_PREFIXI_MACRO_declare_safe_opv(_OP) \
  static inline _Bool safe_##_OP##v(void *dst, size_t args, ...) { \
    struct sio_arg_t total = {0}; \
    va_list ap; \
 \
    va_start(ap, args); \
    /* Grab the first argument so we can prep total */ \
    { \
      const struct sio_arg_t *const lhs = va_arg(ap, const struct sio_arg_t *const); \
      if (!lhs) return 0; \
 \
      total.bits = lhs->bits; \
      total.sign = lhs->sign; \
      /* Copy over using the largest supported type */ \
      total.v.ull = lhs->v.ull; \
     } \
 \
    while (--args) { \
      const struct sio_arg_t *const rhs = va_arg(ap, const struct sio_arg_t *const); \
      if (!rhs) return 0; \
      /* XXX: test to ensure passing the v.ull works for any type in the union */ \
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

__sioi(m)(declare_safe_opv)(add)
__sioi(m)(declare_safe_opv)(sub)
__sioi(m)(declare_safe_opv)(mul)
__sioi(m)(declare_safe_opv)(div)
__sioi(m)(declare_safe_opv)(mod)
__sioi(m)(declare_safe_opv)(shl)
__sioi(m)(declare_safe_opv)(shr)

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


#endif  /* _SAFE_IOP_H */
