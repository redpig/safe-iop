/* safe_iop
 * License:: BSD
 * Author:: Will Drewry <redpig@dataspill.org>
 *
 * See README for use.
 * This library uses a few prefixes:
 * - safe_* for interface macros
 * - sio_* for internal, but exposed interface macros
 *
 * To Do:
 * - change prefix or consistency -- maybe sil_
 * - Autogenerate test cases for all op-type-type combinations
 * - Test out with other compilers
 * - Consider ways to do safe casting with operator awareness to
 *   allow cases where an addition of a negative signed value may be safe
 *   as a subtraction, for example. (Perhaps using checked type promotion
 *   similarly to compilers)
 *
 * History:
 * = 0.4
 * - Compiles under pcc
 * - Added pointer type markup which allows for (e.g.) u64=u32+u32.
 * - Rewrote to support passing consts and compilers without typeof()
 * -- added safe_<op>x  -- primary interface
 * -- added safe_<op>x[num] - convenience interface
 * -- added safe_incx and safe_decx
 * - refactored nearly all of the code
 * - Removed -DSAFE_IOP_COMPAT
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
 * - thanks to Google for contributing some work upstream earlier in the project
 *
 * Copyright (c) 2007,2008 Will Drewry <redpig@dataspill.org>
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
 */
#ifndef _SAFE_IOP_H
#define _SAFE_IOP_H
#include <stdint.h> /* [u]int<bits>_t */
#include <sys/types.h> /* for [s]size_t */
#include <limits.h>  /* for CHAR_BIT */
#include <assert.h>  /* for convenience NULL check  */
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

#define SAFE_IOP_TYPE_PREFIXES "us"

/* safe_iopf
 *
 * Takes in a character array which specifies the operations
 * to perform on a given value. The value will be assumed to be
 * of the type specified for each operation.
 *
 * Currently accepted format syntax is:
 *   [type_marker]operation[type_marker]...
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
 * - *   -- multiplication
 * - /   -- division
 * - -   -- subtraction
 * - +   -- addition
 * - %   -- modulo (remainder)
 * - <<  -- left shift
 * - >>  -- right shift
 *
 * Args:
 * - pointer to the final result
 * - array of format characters
 * - all remaining arguments are derived from the format
 * Output:
 * - Returns 1 on success leaving the result in value
 * - Returns 0 on failure leaving the contents of value *unknown*
 * Caveats:
 * - This function is only provided if safe_iop.c is compiled and linked
 *   into the source.  Otherwise only macro-based functions are available.
 */
int safe_iopf(void *result, const char *const fmt, ...);


/* Type markup macros
 * These macros are the user mechanism for marking up
 * types without giving the exact type name.  This
 * serves primarily as short-hand for long type names,
 * but also provides a simple mechanism for automatically
 * getting whether a type is signed in a programmatic fashion.
 *
 * These are used _only_ with the generic compiler interfaces
 * and not with the GNU C compiler interfaces. See the comment
 * at the start of the "Generic (x) interface macros" section
 * for example usage.
 */
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

/* This allows NULL to be passed in to the generic
 * interface macros without needing to mark them up
 * with a type (like sio_blah(NULL)). Instead, NULL
 * will work.
 */
#define sio_typeof_NULL intmax_t  /* silences gcc complaints when the macos expand */
#define sio_signed_NULL 0
#define sio_valueof_NULL 0


/*****************************************************************************
 * Safe-checking Implementation Macros
 *****************************************************************************
 * The macros below are used for the implementation of the specific
 * operation (along with helpers).  Each operation will take the format:
 *   sio_[u|s]<op>(...)
 * 'u' and 's' represent unsigned and signed checks, respectively. The macros
 * take the sign and type for both operands, but only the sign and type of the
 * first operand, 'a', is used for the operation.  These macros assume
 * type-casting is safe on the given operands when they are called. (The
 * sio_safe_cast macro in this section performs just that test.)  Despite this,
 * the sign and type of the second operand, 'b', have been left in in case of
 * future need.
 */

/* sio_assert
 * An assert() wrapper which still performs the operation when NDEBUG called
 * and is safe in if statements.
 */
#ifdef NDEBUG
#  define sio_assert(x) ((x) ? 1 : 0)
#else
#  define sio_assert(x) (assert(x),1)
#endif

/* use a nice prefix :) */
#define __sio(x) OPAQUE_SAFE_IOP_PREFIX_ ## x
#define OPAQUE_SAFE_IOP_PREFIX_var(x) OPAQUE_SAFE_IOP_PREFIX_VARIABLE_ ## x
#define OPAQUE_SAFE_IOP_PREFIX_m(x) OPAQUE_SAFE_IOP_PREFIX_MACRO_ ## x
#define OPAQUE_SAFE_IOP_PREFIX_f(x) OPAQUE_SAFE_IOP_PREFIX_FN_ ## x


/* Determine maximums and minimums for the platform dynamically
 * without relying on a limits.h file.  As a bonus, the compiler
 * may be able to optimize the expression out at compile-time since
 * it should resolve all values to fixed numbers.
 */
#define OPAQUE_SAFE_IOP_PREFIX_MACRO_smin(_type) \
  (_type)((_type)(~0)<<(sizeof(_type)*CHAR_BIT-1))

#define OPAQUE_SAFE_IOP_PREFIX_MACRO_smax(_type) \
   (_type)(-(OPAQUE_SAFE_IOP_PREFIX_MACRO_smin(_type)+1))

#define OPAQUE_SAFE_IOP_PREFIX_MACRO_umax(_type) ((_type)~0)


/*** Same-type addition macros ***/
#define safe_uadd(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) ( \
  (/* safety check */ \
   ((_ptr_type)(_b) <= \
      ((_ptr_type)(__sio(m)(umax)(_ptr_type) - \
       (_ptr_type)(_a))) ? 1 : 0)) \
  ? \
    ((_ptr) != 0 ? \
      *((_ptr_type *)(_ptr)) = ((_ptr_type)(_a) + (_ptr_type)(_b)), 1 : 1) \
  : 0)


#define safe_sadd(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
   (((((_ptr_type)(_b) > (_ptr_type)0) && \
       ((_ptr_type)(_a) > (_ptr_type)0)) \
     ? /*>0*/  \
       ((_ptr_type)(_a) > \
         (_ptr_type)(__sio(m)(smax)(_ptr_type) - \
         (_ptr_type)(_b)) ? 0 : 1) \
     : \
       /* <0 */ \
       ((!((_ptr_type)(_b) > (_ptr_type)0) && \
                !((_ptr_type)(_a) > (_ptr_type)0)) ? \
         (((_ptr_type)(_a) < \
           (_ptr_type)(__sio(m)(smin)(_ptr_type) - \
                             (_ptr_type)(_b))) ? 0 : 1) : 1) \
     ) \
   ? /* Now assign if needed */ \
     ((_ptr) != 0 ? \
       *((_ptr_type *)(_ptr)) = ((_ptr_type)(_a) + (_ptr_type)(_b)),\
       1 \
       : \
       1 \
     ) \
   : \
     0 \
   )

/*** Same-type subtraction macros ***/
#define safe_usub(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((_ptr_type)(_a) >= (_ptr_type)(_b) ? ((_ptr) != 0 ? \
    *((_ptr_type*)(_ptr)) = ((_ptr_type)(_a) - (_ptr_type)(_b)),1 : 1) : 0 )

#define safe_ssub(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) ( \
  (!((_ptr_type)(_b) <= 0 && \
     (_ptr_type)(_a) > (__sio(m)(smax)(_ptr_type) + (_ptr_type)(_b))) && \
   !((_ptr_type)(_b) > 0 && \
     (_ptr_type)(_a) < (__sio(m)(smin)(_ptr_type) + (_ptr_type)(_b)))) \
  ? \
    ((_ptr) != 0 ? *((_ptr_type *)(_ptr)) = \
                    ((_ptr_type)(_a) - (_ptr_type)(_b)), 1 : 1) \
  : \
    0)


/*** Same-type multiplication macros ***/
#define safe_umul(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) ( \
  (!(_ptr_type)(_b) || \
   (_ptr_type)(_a) <= (__sio(m)(umax)(_ptr_type) / (_ptr_type)(_b))) \
  ? \
    (((_ptr) != 0) ? *((_ptr_type*)(_ptr)) = \
                        ((_ptr_type)(_a)) * ((_ptr_type)(_b)),1 : 1) \
  : \
    0)

#define safe_smul(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((((_ptr_type)(_a) > 0) ?  /* a is positive */ \
    (((_ptr_type)(_b) > 0) ?  /* b and a are positive */ \
       (((_ptr_type)(_a) > (__sio(m)(smax)(_ptr_type) / ((_ptr_type)(_b)))) ? 0 : 1) \
     : /* a positive, b non-positive */ \
       (((_ptr_type)(_b) < (__sio(m)(smin)(_ptr_type) / (_ptr_type)(_a))) ? 0 : 1)) \
   : /* a is non-positive */ \
    (((_ptr_type)(_b) > 0) ? /* a is non-positive, b is positive */ \
      (((_ptr_type)(_a) < (__sio(m)(smin)(_ptr_type) / ((_ptr_type)(_b)))) ? 0 : 1) \
     : /* a and b are non-positive */ \
      ((((_ptr_type)(_a) != 0) && \
       (((_ptr_type)(_b)) < (__sio(m)(smax)(_ptr_type) / (_ptr_type)(_a)))) ? \
         0 : 1) \
      ) \
  ) /* end if a and b are non-positive */ \
  ? \
    ((_ptr) != 0 ? *((_ptr_type*)(_ptr)) = \
      ((_ptr_type)(_a) * ((_ptr_type)(_b))),1 : 1) \
  : 0)

/*** Same-type division macros ***/

/* div-by-zero is the only thing addressed */
#define safe_udiv(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_ptr_type)(_b) != 0) ? (((_ptr) != 0) ? \
                  *((_ptr_type*)(_ptr)) = ((_ptr_type)(_a) / (_ptr_type)(_b)),1 : \
                   1) \
              : 0)

/* Addreses div by zero and smin -1 */
#define safe_sdiv(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_ptr_type)(_b) != 0 && (((_ptr_type)(_a) != __sio(m)(smin)(_ptr_type)) || \
    ((_ptr_type)(_b) != (_ptr_type)-1))) \
   ? \
    (((_ptr) != 0) ? *((_ptr_type*)(_ptr)) = \
      ((_ptr_type)(_a) / (_ptr_type)(_b)),1 : 1) \
  : \
    0 \
  ) \


/*** Same-type modulo macros ***/
/* mod-by-zero is the only thing addressed */
#define safe_umod(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_ptr_type)(_b) != 0) ? (((_ptr) != 0) ? \
    *((_ptr_type*)(_ptr)) = ((_ptr_type)(_a) % (_ptr_type)(_b)),1 : 1) : 0)

/* Addreses mod by zero and smin -1 */
#define safe_smod(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_ptr_type)(_b) != 0 && (((_ptr_type)(_a) != __sio(m)(smin)(_ptr_type)) || \
    ((_ptr_type)(_b) != (_ptr_type)-1))) \
   ? \
    (((_ptr) != 0) ? *((_ptr_type*)(_ptr)) = \
      ((_ptr_type)(_a) % (_ptr_type)(_b)),1 : 1) \
  : \
    0 \
  ) \

/*** Same-type left-shift macros ***/
#define safe_sshl(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((((_ptr_type)(_a) < 0) || \
      ((_ptr_type)(_b) < 0) || \
      ((_ptr_type)(_b) >= sizeof(_ptr_type)*CHAR_BIT) || \
      ((_ptr_type)(_a) > (__sio(m)(smax)(_ptr_type) >> (_ptr_type)(_b)))) ? \
    0 \
  : (((_ptr) != 0) ? *((_ptr_type*)(_ptr)) = \
      (_ptr_type)(_a) << (_ptr_type)(_b),1 : 1))

#define safe_ushl(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((((_ptr_type)(_b) >= sizeof(_ptr_type)*CHAR_BIT) || \
      ((_ptr_type)(_a) > (__sio(m)(umax)(_ptr_type) >> (_ptr_type)(_b)))) ? \
    0 \
  : \
    (((_ptr) != 0) ? *((_ptr_type*)(_ptr)) = \
      (_ptr_type)(_a) << (_ptr_type)(_b),1 :  1))

/*** Same-type right-shift macros ***/
/* XXX: CERT doesnt recommend failing on -a, but it is undefined */
#define safe_sshr(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  ((!((_ptr_type)(_a) > 0 || (_ptr_type)(_a) == 0) || \
      !((_ptr_type)(_b) > 0 || (_ptr_type)(_b) == 0) || \
      ((_ptr_type)(_b) >= sizeof(_ptr_type)*CHAR_BIT)) ? \
    0 \
  : \
    (((_ptr) != 0) ? *((_ptr_type*)(_ptr)) = \
      (_ptr_type)(_a) >> (_ptr_type)(_b),1 : 1) \
  )

/* this doesn't whine if 0 >> n. */
#define safe_ushr(_ptr_sign, _ptr_type, _ptr, \
                  _a_sign, _a_type, _a, _b_sign, _b_type, _b) \
  (((_ptr_type)(_b) >= (sizeof(_ptr_type)*CHAR_BIT)) ? \
    0 : (((_ptr) != 0) ? \
         *((_ptr_type*)(_ptr)) = ((_ptr_type)(_a) >> (_ptr_type)(_b)),1 : 1))


/* sio_safe_cast
 * sio_safe_cast takes the signedness, type, and value of two variables. It
 * then returns true if second variable can be safely cast to the first
 * variable's type and sign without changing value.
 *
 * This function is used internally in safe-iop but is exposed to allow
 * use if there is a need.
 */
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
              ((__sio(m)(smax)(_a_type) >= __sio(m)(umax)(_b_type)) \
              ? \
                 1 \
              : \
                /* This will safely truncate given that smax(a) <= umax(b) */ \
                (((_b) < (_b_type)__sio(m)(smax)(_a_type) || \
                 (_b) == (_b_type)__sio(m)(smax)(_a_type)) \
                ? \
                  1 \
                : \
                  0 \
                ) \
              ) \
            : \
              0 \
            ) \
          ) \
        ) \
      ) \
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
               (((_a_type)(_b) < __sio(m)(umax)(_a_type)) || \
                ((_a_type)(_b) == __sio(m)(umax)(_a_type)))) \
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
  )

/*****************************************************************************
 * Generic (x) interface macros
 *****************************************************************************
 * These macros are known to work with GCC as well as PCC and perhaps other C99
 * compatible compilers.  Due to the limitations of the C99 standard, these
 * macros are _NOT_ side effect free and the arguments require a custom
 * type-markup.
 *
 * Instead of requiring the specification of the type for each variable,
 * short-hand macros are provided which provide a simple interface:
 *   uint32_t a = 100, b = 200;
 *   uint64_t c;
 *   if (!safe_mulx(sio_u64(&c), sio_u32(a), sio_u32(b)) abort();
 * In addition, this interface automatically handles testing for cast-safety.
 * All operands will be cast to the type/signedness of the left-most operand unless
 * there is a destination pointer. If there is a pointer, as above, the values will
 * be cast to that type, if possible, for the operations.
 * 
 * Ιn the example above, that is a's type: uint32_t.
 *
 * The type markup macros available are listed at the top of the file.
 *
 * With respect to side effects, never call safe_<op>x[#] with a operand that
 * may have side effects. For example:
 * [BAD!]  safe_addx(buf++, sio_s32(a--), sio_s16(--b));
 *
 */

#define safe_addx(_ptr, _a, _b) \
(sio_valueof_##_ptr == 0 ? \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_a ? \
      safe_sadd(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    :  \
      safe_uadd(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
  : 0) \
 : \
  (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a) && \
   sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_ptr ? \
      safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    : \
      safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0) \
)

#define safe_subx(_ptr, _a, _b) \
(sio_valueof_##_ptr == 0 ? \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_a ? \
      safe_ssub(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    :  \
      safe_usub(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
  : 0) \
 : \
  (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a) && \
   sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_ptr ? \
      safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    : \
      safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0) \
)

#define safe_mulx(_ptr, _a, _b) \
(sio_valueof_##_ptr == 0 ? \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_a ? \
      safe_smul(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    :  \
      safe_umul(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
  : 0) \
 : \
  (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a) && \
   sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_ptr ? \
      safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    : \
      safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0) \
)

#define safe_divx(_ptr, _a, _b) \
(sio_valueof_##_ptr == 0 ? \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_a ? \
      safe_sdiv(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    :  \
      safe_udiv(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
  : 0) \
 : \
  (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a) && \
   sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_ptr ? \
      safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    : \
      safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0) \
)

#define safe_modx(_ptr, _a, _b) \
(sio_valueof_##_ptr == 0 ? \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_a ? \
      safe_smod(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    :  \
      safe_umod(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
  : 0) \
 : \
  (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a) && \
   sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_ptr ? \
      safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    : \
      safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0) \
)


#define safe_shlx(_ptr, _a, _b) \
(sio_valueof_##_ptr == 0 ? \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_a ? \
      safe_sshl(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    :  \
      safe_ushl(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
  : 0) \
 : \
  (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a) && \
   sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_ptr ? \
      safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    : \
      safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0) \
)

#define safe_shrx(_ptr, _a, _b) \
(sio_valueof_##_ptr == 0 ? \
  (sio_safe_cast(sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_a ? \
      safe_sshr(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    :  \
      safe_ushr(sio_signed_##_a, sio_typeof_##_a, 0, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
  : 0) \
 : \
  (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a) && \
   sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                 sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) ? \
    (sio_signed_##_ptr ? \
      safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b) \
    : \
      safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                sio_signed_##_a, sio_typeof_##_a, sio_valueof_##_a, \
                sio_signed_##_b, sio_typeof_##_b, sio_valueof_##_b)) \
    : 0) \
)

/* Generic interface convenience functions */

/* safe_incx
 * Increments the value stored in a variable by one.
 * Example:
 *   int i;
 *   for (i = 0; i <= max && safe_incx(sio_s32(i); ) { ... }
 * This will increment until i == max or the variable would overflow (i=INT_MAX).
 */
#define safe_incx(_p) \
  (sio_signed_##_p ? \
    safe_sadd(sio_signed_##_p, sio_typeof_##_p, &(sio_valueof_##_p), \
              sio_signed_##_p, sio_typeof_##_p, sio_valueof_##_p, \
              sio_signed_##_p, sio_typeof_##_p, 1) : \
    safe_uadd(sio_signed_##_p, sio_typeof_##_p, &(sio_valueof_##_p), \
              sio_signed_##_p, sio_typeof_##_p, sio_valueof_##_p, \
              sio_signed_##_p, sio_typeof_##_p, 1))

/* safe_decx
 * Decrements the value stored in a variable by one.
 * Example:
 *   unsigned int i = 1024;
 *   while (safe_decx(sio_u32(i)) { ... }
 * This will decrement until the variablewould underflow (i==0).
 */
#define safe_decx(_p) \
  (sio_signed_##_p ? \
    safe_ssub(sio_signed_##_p, sio_typeof_##_p, &(sio_valueof_##_p), \
              sio_signed_##_p, sio_typeof_##_p, sio_valueof_##_p, \
              sio_signed_##_p, sio_typeof_##_p, 1) : \
    safe_usub(sio_signed_##_p, sio_typeof_##_p, &(sio_valueof_##_p), \
              sio_signed_##_p, sio_typeof_##_p, sio_valueof_##_p, \
              sio_signed_##_p, sio_typeof_##_p, 1))

/* safe_<op>x[3-5]
 * These functions allow for the easy repetition of the same operation.
 * For instance, safe_mulx3 will multiply 3 integers together if they can
 * be safely cast to the type of the destination pointer and do not result
 * in an overflow or underflow.
 *
 * For example:
 *   if (!safe_mulx3(sio_u32(&image_sz), sio_u32(w), sio_u32(h), sio_u16(depth)))
 *     goto ERR_handle_bad_dimensions;
 */
#define safe_addx3(_ptr, _A, _B, _C) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
       sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
       sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        :  \
          safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_addx4(_ptr, _A, _B, _C, _D) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        :  \
          safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_addx5(_ptr, _A, _B, _C, _D, _E) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_sadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        :  \
          safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_uadd(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_subx3(_ptr, _A, _B, _C) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        :  \
          safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_subx4(_ptr, _A, _B, _C, _D) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        :  \
          safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_subx5(_ptr, _A, _B, _C, _D, _E) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_ssub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        :  \
          safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_usub(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_mulx3(_ptr, _A, _B, _C) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        :  \
          safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_mulx4(_ptr, _A, _B, _C, _D) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        :  \
          safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_mulx5(_ptr, _A, _B, _C, _D, _E) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_smul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        :  \
          safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_umul(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_divx3(_ptr, _A, _B, _C) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        :  \
          safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_divx4(_ptr, _A, _B, _C, _D) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        :  \
          safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_divx5(_ptr, _A, _B, _C, _D, _E) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_sdiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        :  \
          safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_udiv(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_modx3(_ptr, _A, _B, _C) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        :  \
          safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_modx4(_ptr, _A, _B, _C, _D) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        :  \
          safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_modx5(_ptr, _A, _B, _C, _D, _E) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_smod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        :  \
          safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_umod(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_shlx3(_ptr, _A, _B, _C) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        :  \
          safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_shlx4(_ptr, _A, _B, _C, _D) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        :  \
          safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_shlx5(_ptr, _A, _B, _C, _D, _E) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_sshl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        :  \
          safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_ushl(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_shrx3(_ptr, _A, _B, _C) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        :  \
          safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_shrx4(_ptr, _A, _B, _C, _D) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        :  \
          safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )

#define safe_shrx5(_ptr, _A, _B, _C, _D, _E) \
    (sio_assert((sio_valueof_##_ptr) != 0) \
    ? \
      (sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
      sio_safe_cast(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
                     sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
      ? \
        (sio_signed_##_ptr \
        ? \
          safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_sshr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        :  \
          safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_A, sio_typeof_##_A, sio_valueof_##_A, \
            sio_signed_##_B, sio_typeof_##_B, sio_valueof_##_B) && \
          safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_C, sio_typeof_##_C, sio_valueof_##_C) && \
          safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_D, sio_typeof_##_D, sio_valueof_##_D) && \
          safe_ushr(sio_signed_##_ptr, sio_typeof_##_ptr, sio_valueof_##_ptr, \
            sio_signed_##_ptr, sio_typeof_##_ptr, \
              (*(sio_typeof_##_ptr *)(sio_valueof_##_ptr)), \
            sio_signed_##_E, sio_typeof_##_E, sio_valueof_##_E) \
        ) \
      : \
        0 \
      ) \
    : \
      0 \
    )


/*****************************************************************************
 * GNU C interface macros
 *****************************************************************************
 * The macros below make use of two GNU C extensions:
 * - statement blocks as expressions ({ ... })
 * - typeof()
 * These functions act as convenience interfaces for GCC users, but lack the
 * breadth of functionality of the generic interface.
 * Benefits:
 * - side-effect-less macros: (safe_add(cur++, ...) is OK)
 * - no type markup: less work from you
 * Limitations:
 * - Casts to the type of the first operand (a) instead of the pointer
 * - Cannot handle types with special attributes, like 'const'
 *
 * Αs with the 'x' interfaces, _dst can be NULL.  However, this also extends to
 * the convenience functions like safe_add3() unlike in the generic interface.
 */

#if defined(__GNUC__)

/* Helpers for the GNUC interface */
#define OPAQUE_SAFE_IOP_PREFIX_MACRO_is_signed(__sA) \
  (OPAQUE_SAFE_IOP_PREFIX_MACRO_smin(typeof(__sA)) <= ((typeof(__sA))0))

/* Actual interface */
#define safe_add(_dst, _A, _B) ({ \
  /* Protect against side effects */ \
  typeof(_A) __sio(var)(_a) = (_A); \
  typeof(_B) __sio(var)(_b) = (_B); \
  typeof(_A) *__sio(var)(_ptr) = (_dst); \
  _Bool __sio(var)(ok) =  \
    (sio_safe_cast(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                   __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) ? \
      ( __sio(m)(is_signed)(_A) ? \
          safe_sadd(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr),\
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) \
        :  \
          safe_uadd(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr), \
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b))) \
      : 0 ); \
   __sio(var)(ok); \
})

#define safe_sub(_dst, _A, _B) ({ \
  /* Protect against side effects */ \
  typeof(_A) __sio(var)(_a) = (_A); \
  typeof(_B) __sio(var)(_b) = (_B); \
  typeof(_A) *__sio(var)(_ptr) = (_dst); \
  _Bool __sio(var)(ok) =  \
    (sio_safe_cast(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                   __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) ? \
      ( __sio(m)(is_signed)(_A) ? \
          safe_ssub(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr),\
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) \
        :  \
          safe_usub(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr), \
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b))) \
      : 0 ); \
   __sio(var)(ok); \
})

#define safe_mul(_dst, _A, _B) ({ \
  /* Protect against side effects */ \
  typeof(_A) __sio(var)(_a) = (_A); \
  typeof(_B) __sio(var)(_b) = (_B); \
  typeof(_A) *__sio(var)(_ptr) = (_dst); \
  _Bool __sio(var)(ok) =  \
    (sio_safe_cast(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                   __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) ? \
      ( __sio(m)(is_signed)(_A) ? \
          safe_smul(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr),\
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) \
        :  \
          safe_umul(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr), \
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b))) \
      : 0 ); \
   __sio(var)(ok); \
})

#define safe_div(_dst, _A, _B) ({ \
  /* Protect against side effects */ \
  typeof(_A) __sio(var)(_a) = (_A); \
  typeof(_B) __sio(var)(_b) = (_B); \
  typeof(_A) *__sio(var)(_ptr) = (_dst); \
  _Bool __sio(var)(ok) =  \
    (sio_safe_cast(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                   __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) ? \
      ( __sio(m)(is_signed)(_A) ? \
          safe_sdiv(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr),\
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) \
        :  \
          safe_udiv(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr), \
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b))) \
      : 0 ); \
   __sio(var)(ok); \
})

#define safe_mod(_dst, _A, _B) ({ \
  /* Protect against side effects */ \
  typeof(_A) __sio(var)(_a) = (_A); \
  typeof(_B) __sio(var)(_b) = (_B); \
  typeof(_A) *__sio(var)(_ptr) = (_dst); \
  _Bool __sio(var)(ok) =  \
    (sio_safe_cast(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                   __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) ? \
      ( __sio(m)(is_signed)(_A) ? \
          safe_smod(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr),\
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) \
        :  \
          safe_umod(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr), \
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b))) \
      : 0 ); \
   __sio(var)(ok); \
})

#define safe_shl(_dst, _A, _B) ({ \
  /* Protect against side effects */ \
  typeof(_A) __sio(var)(_a) = (_A); \
  typeof(_B) __sio(var)(_b) = (_B); \
  typeof(_A) *__sio(var)(_ptr) = (_dst); \
  _Bool __sio(var)(ok) =  \
    (sio_safe_cast(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                   __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) ? \
      ( __sio(m)(is_signed)(_A) ? \
          safe_sshl(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr),\
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) \
        :  \
          safe_ushl(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr), \
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b))) \
      : 0 ); \
   __sio(var)(ok); \
})

#define safe_shr(_dst, _A, _B) ({ \
  /* Protect against side effects */ \
  typeof(_A) __sio(var)(_a) = (_A); \
  typeof(_B) __sio(var)(_b) = (_B); \
  typeof(_A) *__sio(var)(_ptr) = (_dst); \
  _Bool __sio(var)(ok) =  \
    (sio_safe_cast(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                   __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) ? \
      ( __sio(m)(is_signed)(_A) ? \
          safe_sshr(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr),\
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b)) \
        :  \
          safe_ushr(__sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_ptr), \
                    __sio(m)(is_signed)(_A), typeof(_A), __sio(var)(_a), \
                    __sio(m)(is_signed)(_B), typeof(_B), __sio(var)(_b))) \
      : 0 ); \
   __sio(var)(ok); \
})

/* Helper macros for performing repeated operations in one call */

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

#define safe_shl3(_ptr, _A, _B, _C) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_shl(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_shl((_ptr), __sio(var)(r), __sio(var)(c))); })

#define safe_shl4(_ptr, _A, _B, _C, _D) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_shl(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_shl(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
    safe_shl((_ptr), __sio(var)(r), (__sio(var)(d)))); })

#define safe_shl5(_ptr, _A, _B, _C, _D, _E) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C), \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_E) __sio(var)(e) = (_E); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_shl(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_shl(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
    safe_shl(&(__sio(var)(r)), __sio(var)(r), __sio(var)(d)) && \
    safe_shl((_ptr), __sio(var)(r), __sio(var)(e))); })

#define safe_shr3(_ptr, _A, _B, _C) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_shr(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_shr((_ptr), __sio(var)(r), __sio(var)(c))); })

#define safe_shr4(_ptr, _A, _B, _C, _D) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C); \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_shr(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_shr(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
    safe_shr((_ptr), __sio(var)(r), (__sio(var)(d)))); })

#define safe_shr5(_ptr, _A, _B, _C, _D, _E) \
({ typeof(_A) __sio(var)(a) = (_A); \
   typeof(_B) __sio(var)(b) = (_B); \
   typeof(_C) __sio(var)(c) = (_C), \
   typeof(_D) __sio(var)(d) = (_D); \
   typeof(_E) __sio(var)(e) = (_E); \
   typeof(_A) __sio(var)(r) = 0; \
   (safe_shr(&(__sio(var)(r)), __sio(var)(a), __sio(var)(b)) && \
    safe_shr(&(__sio(var)(r)), __sio(var)(r), __sio(var)(c)) && \
    safe_shr(&(__sio(var)(r)), __sio(var)(r), __sio(var)(d)) && \
    safe_shr((_ptr), __sio(var)(r), __sio(var)(e))); })

#define safe_inc(_a)  safe_add(&(_a), (_a), 1)
#define safe_dec(_a)  safe_add(&(_a), (_a), 1)

#endif /* __GNUC__ */

#endif  /* _SAFE_IOP_H */
