/* safe_iop
 * Author:: Will Drewry <redpig@dataspill.org>
 * See safe_iop.h for more info.
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
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

#include <safe_iop.h>

/* _safe_op_read_type
 * This is a static helper function for safe_iopf which reads off
 * the type from the format string and advances the given pointer.
 */
static int _safe_op_read_type(safe_type_t *type, const char **c) {
  if (type == NULL) {
    return 0;
  }

  if (c == NULL || *c == NULL) {
    return 0;
  }

  /* Leave it as default if end of fmt */
  if (**c == '\0')
    return 1;

  /* Extract a type for the operation if there is one */
  if (strchr(SAFE_IOP_TYPE_PREFIXES, **c) != NULL) {
    switch(**c) {
      case 'u':
        if (*(*c+1) && *(*c+1) == '8') {
          *type = SAFE_IOP_TYPE_U8;
          *c += 2; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '1') &&
                   (*(*c+2) && *(*c+2) == '6')) {
          *type = SAFE_IOP_TYPE_U16;
          *c += 3; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '3') &&
                   (*(*c+2) && *(*c+2) == '2')) {
          *type = SAFE_IOP_TYPE_U32;
          *c += 3; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '6') &&
                   (*(*c+2) && *(*c+2) == '4')) {
          *type = SAFE_IOP_TYPE_U64;
          *c += 3; /* Advance past type */
        }
        break;
      case 's':
        if (*(*c+1) && *(*c+1) == '8') {
          *type = SAFE_IOP_TYPE_S8;
          *c += 2; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '1') &&
                   (*(*c+2) && *(*c+2) == '6')) {
          *type = SAFE_IOP_TYPE_S16;
          *c += 3; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '3') &&
                   (*(*c+2) && *(*c+2) == '2')) {
          *type = SAFE_IOP_TYPE_S32;
          *c += 3; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '6') &&
                   (*(*c+2) && *(*c+2) == '4')) {
          *type = SAFE_IOP_TYPE_S64;
          *c += 3; /* Advance past type */
        }
        break;
      default:
        /* Unknown type */
        return 0;
    }
  }
  return 1;
}

/* Repeated code for va_args is here.  More code is not factored out this
 * way due to the C99 4096 byte limit for expanded macro text.  */
#define _SAFE_IOP_TYPE_CASE(_lhs, _va_lhs, _lhs_a, _rhs, _va_rhs, _rhs_a, _func) { \
  _rhs a; \
  _lhs value, *_h = (_lhs *) holder; \
  if (!baseline) { \
    value = (_lhs) va_arg(ap, _va_lhs); \
    a = (_rhs) va_arg(ap, _va_rhs); \
    baseline = 1; \
  } else { \
    value = *_h; \
    a = (_rhs) va_arg(ap, _va_rhs); \
  } \
  if (! _func(sio_##_lhs_a(_h), sio_##_lhs_a(value), sio_##_rhs_a(a))) \
    return 0; \
}


/* See header file for details. Or the README :) */
int safe_iopf(void *result, const char *const fmt, ...) {
  va_list ap;
  int baseline = 0; /* indicates if the base value is present */

  const char *c = NULL;
  /* Holds the interim values and allows for result to be NULL. */
  unsigned char holder[sizeof(intmax_t)] = {0};
  safe_type_t lhs = SAFE_IOP_TYPE_DEFAULT, rhs = SAFE_IOP_TYPE_DEFAULT;

  va_start(ap, fmt);
  if (fmt == NULL || fmt[0] == '\0')
    return 0;

  /* Read the left-hand side type for the operation type if giveṅ.
   * safe_iop(f) always casts to the left so this is only read once
   * then carried through.
   */
  c=fmt;
  if (!_safe_op_read_type(&lhs, &c)) {
    return 0;
  }

  while (*c) {
    /* Process the the operations */
    switch(*(c++)) { /* operation */
      case '+': /* add */
        /* Read the right-hand side type for the operation type if given */
        if (!_safe_op_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, safe_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, safe_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, safe_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, safe_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, safe_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, safe_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, safe_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, safe_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, safe_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, safe_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, safe_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, safe_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, safe_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, safe_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, safe_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, safe_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, safe_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, safe_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, safe_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, safe_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, safe_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, safe_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, safe_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, safe_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, safe_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, safe_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, safe_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, safe_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, safe_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, safe_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, safe_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, safe_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, safe_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, safe_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, safe_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, safe_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, safe_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, safe_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, safe_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, safe_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, safe_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, safe_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, safe_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, safe_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, safe_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, safe_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, safe_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, safe_addx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, safe_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, safe_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, safe_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, safe_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, safe_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, safe_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, safe_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, safe_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, safe_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, safe_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, safe_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, safe_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, safe_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, safe_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, safe_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, safe_addx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '-': /* sub */
        if (!_safe_op_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, safe_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, safe_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, safe_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, safe_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, safe_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, safe_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, safe_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, safe_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, safe_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, safe_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, safe_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, safe_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, safe_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, safe_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, safe_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, safe_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, safe_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, safe_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, safe_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, safe_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, safe_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, safe_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, safe_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, safe_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, safe_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, safe_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, safe_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, safe_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, safe_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, safe_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, safe_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, safe_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, safe_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, safe_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, safe_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, safe_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, safe_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, safe_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, safe_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, safe_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, safe_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, safe_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, safe_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, safe_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, safe_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, safe_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, safe_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, safe_subx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, safe_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, safe_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, safe_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, safe_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, safe_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, safe_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, safe_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, safe_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, safe_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, safe_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, safe_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, safe_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, safe_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, safe_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, safe_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, safe_subx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '*': /* mul */
        if (!_safe_op_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, safe_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, safe_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, safe_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, safe_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, safe_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, safe_mulx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, safe_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, safe_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, safe_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, safe_mulx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '/': /* div */
        if (!_safe_op_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, safe_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, safe_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, safe_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, safe_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, safe_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, safe_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, safe_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, safe_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, safe_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, safe_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, safe_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, safe_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, safe_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, safe_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, safe_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, safe_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, safe_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, safe_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, safe_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, safe_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, safe_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, safe_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, safe_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, safe_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, safe_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, safe_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, safe_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, safe_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, safe_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, safe_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, safe_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, safe_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, safe_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, safe_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, safe_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, safe_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, safe_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, safe_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, safe_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, safe_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, safe_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, safe_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, safe_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, safe_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, safe_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, safe_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, safe_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, safe_divx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, safe_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, safe_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, safe_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, safe_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, safe_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, safe_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, safe_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, safe_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, safe_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, safe_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, safe_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, safe_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, safe_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, safe_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, safe_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, safe_divx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '%': /* mod */
        if (!_safe_op_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, safe_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, safe_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, safe_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, safe_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, safe_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, safe_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, safe_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, safe_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, safe_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, safe_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, safe_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, safe_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, safe_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, safe_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, safe_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, safe_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, safe_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, safe_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, safe_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, safe_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, safe_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, safe_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, safe_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, safe_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, safe_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, safe_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, safe_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, safe_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, safe_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, safe_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, safe_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, safe_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, safe_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, safe_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, safe_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, safe_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, safe_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, safe_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, safe_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, safe_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, safe_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, safe_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, safe_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, safe_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, safe_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, safe_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, safe_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, safe_modx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, safe_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, safe_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, safe_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, safe_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, safe_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, safe_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, safe_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, safe_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, safe_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, safe_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, safe_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, safe_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, safe_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, safe_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, safe_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, safe_modx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '<': /* shl */
        if (*c && *c == '<') {
          c++;
          if (!_safe_op_read_type(&rhs, &c))
            return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, safe_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, safe_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, safe_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, safe_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, safe_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, safe_shlx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, safe_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, safe_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, safe_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, safe_shlx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
          }
        } else {
          /* unknown op */
          return 0;
        }
        break;
      case '>': /* shr */
        if (*c && *c == '>') {
          c++;
          if (!_safe_op_read_type(&rhs, &c))
            return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, safe_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, safe_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, safe_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, safe_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, safe_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, safe_shrx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, safe_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, safe_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, safe_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, safe_shrx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        } else {
          /* unknown op */
          return 0;
        }
        break;
      default:
       /* unknown op */
       return 0;
    }
    /* Once the lhs type is given, this becomes the default for
     * all remaining operands
     */
   rhs = lhs;
  }
  /* Success! Assign the holder value back to result using the stored lhs */
  if (result) {
    switch (lhs) {
      case SAFE_IOP_TYPE_U8: {
        uint8_t *r = result, *h = (uint8_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_S8: {
        int8_t *r = result, *h = (int8_t *)holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_U16: {
        uint16_t *r = result, *h = (uint16_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_S16: {
        int16_t *r = result, *h = (int16_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_U32: {
        uint32_t *r = result, *h = (uint32_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_S32: {
        int32_t *r = result, *h = (int32_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_U64: {
        uint64_t *r = result, *h = (uint64_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_S64: {
        int64_t *r = result, *h = (int64_t *) holder;
        *r = *h;
        } break;
      default:
        /* bad sign. maybe this should abort. */
        return 0;
    }
  }
  return 1;
}

#ifdef SAFE_IOP_TEST
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>

/* __LP64__ is given by GCC. Without more work, this is bound to GCC. */
#if __LP64__ == 1 || __SIZEOF_LONG__ > __SIZEOF_INT__
#  define SAFE_INT64_MAX 0x7fffffffffffffffL
#  define SAFE_UINT64_MAX 0xffffffffffffffffUL
#  define SAFE_INT64_MIN (-SAFE_INT64_MAX - 1L)
#elif __SIZEOF_LONG__ == __SIZEOF_INT__
#  define SAFE_INT64_MAX 0x7fffffffffffffffLL
#  define SAFE_UINT64_MAX 0xffffffffffffffffULL
#  define SAFE_INT64_MIN (-SAFE_INT64_MAX - 1LL)
#else
#  warning "64-bit support disabled"
#  define SAFE_IOP_NO_64 1
#endif

/* Pull these from GNU's limit.h */
#ifndef LLONG_MAX
#  define LLONG_MAX 9223372036854775807LL
#endif
#ifndef LLONG_MIN
#  define LLONG_MIN (-LLONG_MAX - 1LL)
#endif
#ifndef ULLONG_MAX
#  define ULLONG_MAX 18446744073709551615ULL
#endif

/* Assumes SSIZE_MAX */
#ifndef SSIZE_MIN
#  if SSIZE_MAX == LONG_MAX
#    define SSIZE_MIN LONG_MIN
#  elif SSIZE_MAX == LONG_LONG_MAX
#    define SSIZE_MIN LONG_LONG_MIN
#  else
#    error "SSIZE_MIN is not defined and could not be guessed"
#  endif
#endif

#define EXPECT_FALSE(cmd) { \
  printf("%s:%d:%s: EXPECT_FALSE(" #cmd ") => ", __FILE__, __LINE__, __func__); \
  if ((cmd) != 0) { printf(" FAILED\n"); expect_fail++; r = 0; } \
  else { printf(" PASSED\n"); expect_succ++; } \
  expect++; \
  }
#define EXPECT_TRUE(cmd) { \
  printf("%s:%d:%s: EXPECT_TRUE(" #cmd ") => ", __FILE__, __LINE__, __func__); \
  if ((cmd) != 1) { printf(" FAILED\n"); expect_fail++; r = 0; } \
  else { printf(" PASSED\n"); expect_succ++; } \
  expect++; \
  }
/* Not perfect, but good for basic debugging */
#define EXPECT_EQUAL(lhs,rhs) { \
  printf("%s:%d:%s: EXPECT_EQUAL(" #lhs " == " #rhs ") -> ", \
         __FILE__, __LINE__, __func__); \
  printf("(%d == %d) => ", (int)(lhs), (int)(rhs)); \
  if ((lhs) != (rhs)) { printf(" FAILED\n"); expect_fail++; r = 0; } \
  else { printf(" PASSED\n"); expect_succ++; } \
  expect++; \
  }



static int expect = 0, expect_succ = 0, expect_fail = 0;

/***** ADD *****/
int T_add_s8() {
  int r=1;
  int8_t a, b;
  /* TODO: should this just test safe_sadd and safe_uadd? */
  a=SCHAR_MIN; b=-1; EXPECT_FALSE(safe_addx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MAX; b=1; EXPECT_FALSE(safe_addx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MAX; EXPECT_FALSE(safe_incx(sio_s8(a)));
  a=0; EXPECT_TRUE(safe_incx(sio_s8(a))); EXPECT_TRUE(a==1);
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_s8(a), sio_s8(b)));
  a=-10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_s8(a), sio_s8(b)));
  a=10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_s8(a), sio_s8(b)));
  a=-10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MIN; b=SCHAR_MAX; EXPECT_TRUE(safe_addx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MIN+1; b=-1; EXPECT_TRUE(safe_addx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MAX/2; b=SCHAR_MAX/2; EXPECT_TRUE(safe_addx(NULL, sio_s8(a), sio_s8(b)));
  return r;
}

int T_add_s16() {
  int r=1;
  int16_t a, b;
  a=SHRT_MIN; b=-1; EXPECT_FALSE(safe_addx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MAX; b=1; EXPECT_FALSE(safe_addx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MAX; EXPECT_FALSE(safe_incx(sio_s16(a)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_s16(a), sio_s16(b)));
  a=-10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_s16(a), sio_s16(b)));
  a=10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_s16(a), sio_s16(b)));
  a=-10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MIN; b=SHRT_MAX; EXPECT_TRUE(safe_addx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MIN+1; b=-1; EXPECT_TRUE(safe_addx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MAX/2; b=SHRT_MAX/2; EXPECT_TRUE(safe_addx(NULL, sio_s16(a), sio_s16(b)));
  return r;
}

int T_add_s32() {
  int r=1;
  int32_t a, b;
  a=INT_MIN; b=-1; EXPECT_FALSE(safe_addx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MAX; b=1; EXPECT_FALSE(safe_addx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MAX; EXPECT_FALSE(safe_incx(sio_s32(a)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_s32(a), sio_s32(b)));
  a=-10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_s32(a), sio_s32(b)));
  a=10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_s32(a), sio_s32(b)));
  a=-10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MIN; b=INT_MAX; EXPECT_TRUE(safe_addx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MIN+1; b=-1; EXPECT_TRUE(safe_addx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MAX/2; b=INT_MAX/2; EXPECT_TRUE(safe_addx(NULL, sio_s32(a), sio_s32(b)));
  return r;
}

int T_add_s64() {
  int r=1;
  int64_t a, b;
  a=SAFE_INT64_MIN; b=-1; EXPECT_FALSE(safe_addx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MAX; b=1; EXPECT_FALSE(safe_addx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MAX; EXPECT_FALSE(safe_incx(sio_s64(a)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_s64(a), sio_s64(b)));
  a=-10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_s64(a), sio_s64(b)));
  a=10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_s64(a), sio_s64(b)));
  a=-10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MIN; b=SAFE_INT64_MAX; EXPECT_TRUE(safe_addx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MIN+1; b=-1; EXPECT_TRUE(safe_addx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MAX/2; b=SAFE_INT64_MAX/2; EXPECT_TRUE(safe_addx(NULL, sio_s64(a), sio_s64(b)));
  return r;
}

int T_add_long() {
  int r=1;
  long a, b;
  a=LONG_MIN; b=-1; EXPECT_FALSE(safe_addx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MAX; b=1; EXPECT_FALSE(safe_addx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MAX; EXPECT_FALSE(safe_incx(sio_sl(a)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_sl(a), sio_sl(b)));
  a=-10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_sl(a), sio_sl(b)));
  a=10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_sl(a), sio_sl(b)));
  a=-10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MIN; b=LONG_MAX; EXPECT_TRUE(safe_addx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MIN+1; b=-1; EXPECT_TRUE(safe_addx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MAX/2; b=LONG_MAX/2; EXPECT_TRUE(safe_addx(NULL, sio_sl(a), sio_sl(b)));
  return r;
}
int T_add_longlong() {
  int r=1;
  long long a, b;
  a=LLONG_MIN; b=-1; EXPECT_FALSE(safe_addx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MAX; b=1; EXPECT_FALSE(safe_addx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MAX; EXPECT_FALSE(safe_incx(sio_sll(a)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_sll(a), sio_sll(b)));
  a=-10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_sll(a), sio_sll(b)));
  a=10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_sll(a), sio_sll(b)));
  a=-10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MIN; b=LLONG_MAX; EXPECT_TRUE(safe_addx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MIN+1; b=-1; EXPECT_TRUE(safe_addx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MAX/2; b=LLONG_MAX/2; EXPECT_TRUE(safe_addx(NULL, sio_sll(a), sio_sll(b)));
  return r;
}
int T_add_ssizet() {
  int r=1;
  ssize_t a, b;
  a=SSIZE_MIN; b=-1; EXPECT_FALSE(safe_addx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MAX; b=1; EXPECT_FALSE(safe_addx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MAX; EXPECT_FALSE(safe_incx(sio_sszt(a)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_sszt(a), sio_sszt(b)));
  a=10; b=-11; EXPECT_TRUE(safe_addx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MIN; b=SSIZE_MAX; EXPECT_TRUE(safe_addx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MIN+1; b=-1; EXPECT_TRUE(safe_addx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MAX/2; b=SSIZE_MAX/2; EXPECT_TRUE(safe_addx(NULL, sio_sszt(a), sio_sszt(b)));
  return r;
}

int T_add_u8() {
  int r=1;
  uint8_t a, b;
  a=1; b=UCHAR_MAX; EXPECT_FALSE(safe_addx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX; EXPECT_FALSE(safe_incx(sio_u8(a)));
  a=UCHAR_MAX/2; b=a+2; EXPECT_FALSE(safe_addx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX/2; b=a; EXPECT_TRUE(safe_addx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX/2; b=a+1; EXPECT_TRUE(safe_addx(NULL, sio_u8(a), sio_u8(b)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_u8(a), sio_u8(b)));
  a=0; b=UCHAR_MAX; EXPECT_TRUE(safe_addx(NULL, sio_u8(a), sio_u8(b)));
  return r;
}

int T_add_u16() {
  int r=1;
  uint16_t a, b;
  a=1; b=USHRT_MAX; EXPECT_FALSE(safe_addx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX; EXPECT_FALSE(safe_incx(sio_u16(a)));
  a=USHRT_MAX/2; b=a+2; EXPECT_FALSE(safe_addx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX/2; b=a; EXPECT_TRUE(safe_addx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX/2; b=a+1; EXPECT_TRUE(safe_addx(NULL, sio_u16(a), sio_u16(b)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_u16(a), sio_u16(b)));
  a=0; b=USHRT_MAX; EXPECT_TRUE(safe_addx(NULL, sio_u16(a), sio_u16(b)));
  return r;
}

int T_add_u32() {
  int r=1;
  uint32_t a, b;
  a=1; b=UINT_MAX; EXPECT_FALSE(safe_addx(NULL, sio_u32(a), sio_u32(b)));
  a=UINT_MAX; EXPECT_FALSE(safe_incx(sio_u32(a)));
  a=UINT_MAX/2; b=a+2; EXPECT_FALSE(safe_addx(NULL, sio_u32(a), sio_u32(b)));
  a=UINT_MAX/2; b=a; EXPECT_TRUE(safe_addx(NULL, sio_u32(a), sio_u32(b)));
  a=UINT_MAX/2; b=a+1; EXPECT_TRUE(safe_addx(NULL, sio_u32(a), sio_u32(b)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_u32(a), sio_u32(b)));
  a=0; b=UINT_MAX; EXPECT_TRUE(safe_addx(NULL, sio_u32(a), sio_u32(b)));
  return r;
}

int T_add_u64() {
  int r=1;
  uint64_t a, b;
  a=1; b=SAFE_UINT64_MAX; EXPECT_FALSE(safe_addx(NULL, sio_u64(a), sio_u64(b)));
  a=SAFE_UINT64_MAX; EXPECT_FALSE(safe_incx(sio_u64(a)));
  a=SAFE_UINT64_MAX/2; b=a+2; EXPECT_FALSE(safe_addx(NULL, sio_u64(a), sio_u64(b)));
  a=SAFE_UINT64_MAX/2; b=a; EXPECT_TRUE(safe_addx(NULL, sio_u64(a), sio_u64(b)));
  a=SAFE_UINT64_MAX/2; b=a+1; EXPECT_TRUE(safe_addx(NULL, sio_u64(a), sio_u64(b)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_u64(a), sio_u64(b)));
  a=0; b=SAFE_UINT64_MAX; EXPECT_TRUE(safe_addx(NULL, sio_u64(a), sio_u64(b)));
  return r;
}

int T_add_ulong() {
  int r=1;
  unsigned long a, b;
  a=1; b=ULONG_MAX; EXPECT_FALSE(safe_addx(NULL, sio_ul(a), sio_ul(b)));
  a=ULONG_MAX; EXPECT_FALSE(safe_incx(sio_ul(a)));
  a=ULONG_MAX/2; b=a+2; EXPECT_FALSE(safe_addx(NULL, sio_ul(a), sio_ul(b)));
  a=ULONG_MAX/2; b=a; EXPECT_TRUE(safe_addx(NULL, sio_ul(a), sio_ul(b)));
  a=ULONG_MAX/2; b=a+1; EXPECT_TRUE(safe_addx(NULL, sio_ul(a), sio_ul(b)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_ul(a), sio_ul(b)));
  a=0; b=ULONG_MAX; EXPECT_TRUE(safe_addx(NULL, sio_ul(a), sio_ul(b)));
  return r;
}

int T_add_ulonglong() {
  int r=1;
  unsigned long long a, b;
  a=1; b=ULLONG_MAX; EXPECT_FALSE(safe_addx(NULL, sio_ull(a), sio_ull(b)));
  a=ULLONG_MAX; EXPECT_FALSE(safe_incx(sio_ull(a)));
  a=ULLONG_MAX/2; b=a+2; EXPECT_FALSE(safe_addx(NULL, sio_ull(a), sio_ull(b)));
  a=ULLONG_MAX/2; b=a; EXPECT_TRUE(safe_addx(NULL, sio_ull(a), sio_ull(b)));
  a=ULLONG_MAX/2; b=a+1; EXPECT_TRUE(safe_addx(NULL, sio_ull(a), sio_ull(b)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_ull(a), sio_ull(b)));
  a=0; b=ULLONG_MAX; EXPECT_TRUE(safe_addx(NULL, sio_ull(a), sio_ull(b)));
  return r;
}

int T_add_sizet() {
  int r=1;
  size_t a, b;
  a=1; b=SIZE_MAX; EXPECT_FALSE(safe_addx(NULL, sio_szt(a), sio_szt(b)));
  a=SIZE_MAX; EXPECT_FALSE(safe_incx(sio_szt(a)));
  a=SIZE_MAX/2; b=a+2; EXPECT_FALSE(safe_addx(NULL, sio_szt(a), sio_szt(b)));
  a=SIZE_MAX/2; b=a; EXPECT_TRUE(safe_addx(NULL, sio_szt(a), sio_szt(b)));
  a=SIZE_MAX/2; b=a+1; EXPECT_TRUE(safe_addx(NULL, sio_szt(a), sio_szt(b)));
  a=10; b=11; EXPECT_TRUE(safe_addx(NULL, sio_szt(a), sio_szt(b)));
  a=0; b=SIZE_MAX; EXPECT_TRUE(safe_addx(NULL, sio_szt(a), sio_szt(b)));
  return r;
}

int T_add_mixed() {
  int r=1;
  int8_t a = 1;
  uint8_t b = 2;
  uint16_t c = 3;
  a=1; b=SCHAR_MAX; EXPECT_FALSE(safe_addx(NULL, sio_s8(a), sio_u8(b)));
  a=0; b=SCHAR_MAX+1; EXPECT_FALSE(safe_addx(NULL, sio_s8(a), sio_u8(b)));
  a=1; b=SCHAR_MAX-1; EXPECT_TRUE(safe_addx(NULL, sio_s8(a), sio_u8(b)));
  b=1; c=UCHAR_MAX; EXPECT_FALSE(safe_addx(NULL, sio_u8(b), sio_u16(c)));
  b=0; c=UCHAR_MAX+1; EXPECT_FALSE(safe_addx(NULL, sio_u8(b), sio_u16(c)));
  b=1; c=UCHAR_MAX-1; EXPECT_TRUE(safe_addx(NULL, sio_u8(b), sio_u16(c)));
  b=1; c=UCHAR_MAX-1; EXPECT_TRUE(safe_addx(NULL, sio_u16(c), sio_u8(b)));
  a=1; c=USHRT_MAX; EXPECT_FALSE(safe_addx(NULL, sio_s8(a), sio_u16(c)));
  a=1;b=1;c=USHRT_MAX-3; EXPECT_FALSE(safe_addx3(sio_s8(&a), sio_s8(a), sio_u8(b),
                                                 sio_u16(c)));
                         EXPECT_EQUAL(a, 1);
  a=1;b=1;c=1; EXPECT_TRUE(safe_addx3(sio_s8(&a), sio_s8(a), sio_u8(b), sio_u16(c)));
               EXPECT_EQUAL(a, 3);
  a=1;b=1;c=SCHAR_MAX-3; EXPECT_TRUE(safe_addx3(sio_s8(&a), sio_s8(a), sio_u8(b),
                                                sio_u16(c)));
                         EXPECT_EQUAL(a, SCHAR_MAX-1);
  a=1;b=1;c=SCHAR_MAX-3; EXPECT_FALSE(safe_addx3(NULL, sio_s8(a), sio_u8(b),
                                                 sio_u16(c)));
                         EXPECT_EQUAL(a, 1);
  a=-1;b=10; EXPECT_TRUE(safe_addx(NULL, sio_s8(a), sio_u8(b)));
  /* Signed negative numbers are not allowed, even if the result does
   * not underflow.  This is due to the "safe casting" performed prior to
   * the operation.  Since it is operation ignorant, we can't guess what's
   * safe. This means that safe_sub should be used.
   */
  a=-1;b=10; EXPECT_FALSE(safe_addx(NULL, sio_u8(b), sio_s8(a)));
  a=1;b=10; EXPECT_TRUE(safe_subx(NULL, sio_u8(b), sio_s8(a)));
  a=-1;b=0; EXPECT_FALSE(safe_addx(NULL, sio_u8(b), sio_s8(a)));
  return r;
}

#ifdef __GNUC__
int T_add_increment() {
  int r=1;
  uint16_t a = 1, b = 2, c = 0, d[2]= {0};
  uint16_t *cur = d;
  EXPECT_TRUE(safe_add(cur++, a++, b));
  EXPECT_EQUAL(cur, &d[1]);
  EXPECT_EQUAL(d[0], 3);
  EXPECT_EQUAL(a, 2);
  a = 1; b = 2; c = 1; cur=d;d[0] = 0;
#if 0 /* Not yet implemented */
  EXPECT_TRUE(safe_addv(cur++, 3, sio_u16(a++), sio_u16(b++), sio_u16(c)));
  EXPECT_EQUAL(d[0], 4);
  EXPECT_EQUAL(cur, &d[1]);
  EXPECT_EQUAL(a, 2);
  EXPECT_EQUAL(b, 3);
  EXPECT_EQUAL(c, 1);
#endif
  a = 1; b = 2; cur=d;d[0] = 0;
  EXPECT_TRUE(safe_add(cur++, a++, b++));
  EXPECT_EQUAL(d[0], 3);
  EXPECT_EQUAL(cur, &d[1]);
  EXPECT_EQUAL(a, 2);
  EXPECT_EQUAL(b, 3);

  return r;
}
#endif



/***** SUB *****/
int T_sub_s8() {
  int r=1;
  int8_t a, b;
  a=SCHAR_MIN; b=1; EXPECT_FALSE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MIN; EXPECT_FALSE(safe_decx(sio_s8(a)));
  a=1; EXPECT_TRUE(safe_decx(sio_s8(a))); EXPECT_TRUE(a==0);
  a=SCHAR_MIN; b=SCHAR_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MIN/2; b=SCHAR_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  a=-2; b=SCHAR_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MAX; b=SCHAR_MAX; EXPECT_TRUE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  a=2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  a=-2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  a=2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  a=-2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_s8(a), sio_s8(b)));
  return r;
}

int T_sub_s16() {
  int r=1;
  int16_t a, b;
  a=SHRT_MIN; b=1; EXPECT_FALSE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MIN; EXPECT_FALSE(safe_decx(sio_s16(a)));
  a=SHRT_MIN; b=SHRT_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MIN/2; b=SHRT_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  a=-2; b=SHRT_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MAX; b=SHRT_MAX; EXPECT_TRUE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  a=2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  a=-2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  a=2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  a=-2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_s16(a), sio_s16(b)));
  return r;
}

int T_sub_s32() {
  int r=1;
  int32_t a, b;
  a=INT_MIN; b=1; EXPECT_FALSE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MIN; EXPECT_FALSE(safe_decx(sio_s32(a)));
  a=INT_MIN; b=INT_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MIN/2; b=INT_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  a=-2; b=INT_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MAX; b=INT_MAX; EXPECT_TRUE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  a=2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  a=-2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  a=2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  a=-2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_s32(a), sio_s32(b)));
  return r;
}

int T_sub_s64() {
  int r=1;
  int64_t a, b;
  a=SAFE_INT64_MIN; b=1; EXPECT_FALSE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MIN; EXPECT_FALSE(safe_decx(sio_s64(a)));
  a=SAFE_INT64_MIN; b=SAFE_INT64_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MIN/2; b=SAFE_INT64_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  a=-2; b=SAFE_INT64_MAX; EXPECT_FALSE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MAX; b=SAFE_INT64_MAX; EXPECT_TRUE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  a=2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  a=-2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  a=2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  a=-2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_s64(a), sio_s64(b)));
  return r;
}

int T_sub_long() {
  int r=1;
  long a, b;
  a=LONG_MIN; b=1; EXPECT_FALSE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MIN; EXPECT_FALSE(safe_decx(sio_sl(a)));
  a=LONG_MIN; b=LONG_MAX; EXPECT_FALSE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MIN/2; b=LONG_MAX; EXPECT_FALSE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  a=-2; b=LONG_MAX; EXPECT_FALSE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MAX; b=LONG_MAX; EXPECT_TRUE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  a=2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  a=-2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  a=2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  a=-2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_sl(a), sio_sl(b)));
  return r;
}

int T_sub_longlong() {
  int r=1;
  long long a, b;
  a=LLONG_MIN; b=1; EXPECT_FALSE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MIN; EXPECT_FALSE(safe_decx(sio_sll(a)));
  a=LLONG_MIN; b=LLONG_MAX; EXPECT_FALSE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MIN/2; b=LLONG_MAX; EXPECT_FALSE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  a=-2; b=LLONG_MAX; EXPECT_FALSE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MAX; b=LLONG_MAX; EXPECT_TRUE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  a=2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  a=-2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  a=2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  a=-2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_sll(a), sio_sll(b)));
  return r;
}

int T_sub_ssizet() {
  int r=1;
  ssize_t a, b;
  a=SSIZE_MIN; b=1; EXPECT_FALSE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MIN; EXPECT_FALSE(safe_decx(sio_sszt(a)));
  a=SSIZE_MIN; b=SSIZE_MAX; EXPECT_FALSE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MIN/2; b=SSIZE_MAX; EXPECT_FALSE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-2; b=SSIZE_MAX; EXPECT_FALSE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MAX; b=SSIZE_MAX; EXPECT_TRUE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  a=2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  a=2; b=-10; EXPECT_TRUE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-2; b=10; EXPECT_TRUE(safe_subx(NULL, sio_sszt(a), sio_sszt(b)));
  return r;
}

int T_sub_u8() {
  int r=1;
  uint8_t a, b;
  a=0; b=UCHAR_MAX; EXPECT_FALSE(safe_subx(NULL, sio_u8(a), sio_u8(b)));
  a=0; EXPECT_FALSE(safe_decx(sio_u8(a)));
  a=UCHAR_MAX-1; b=UCHAR_MAX; EXPECT_FALSE(safe_subx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX; b=UCHAR_MAX; EXPECT_TRUE(safe_subx(NULL, sio_u8(a), sio_u8(b)));
  a=1; b=100; EXPECT_FALSE(safe_subx(NULL, sio_u8(a), sio_u8(b)));
  a=100; b=0; EXPECT_TRUE(safe_subx(NULL, sio_u8(a), sio_u8(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_u8(a), sio_u8(b)));
  a=0; b=0; EXPECT_TRUE(safe_subx(NULL, sio_u8(a), sio_u8(b)));
  return r;
}

int T_sub_u16() {
  int r=1;
  uint16_t a, b;
  a=0; b=USHRT_MAX; EXPECT_FALSE(safe_subx(NULL, sio_u16(a), sio_u16(b)));
  a=0; EXPECT_FALSE(safe_decx(sio_u16(a)));
  a=USHRT_MAX-1; b=USHRT_MAX; EXPECT_FALSE(safe_subx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX; b=USHRT_MAX; EXPECT_TRUE(safe_subx(NULL, sio_u16(a), sio_u16(b)));
  a=1; b=100; EXPECT_FALSE(safe_subx(NULL, sio_u16(a), sio_u16(b)));
  a=100; b=0; EXPECT_TRUE(safe_subx(NULL, sio_u16(a), sio_u16(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_u16(a), sio_u16(b)));
  a=0; b=0; EXPECT_TRUE(safe_subx(NULL, sio_u16(a), sio_u16(b)));
  return r;
}

int T_sub_u32() {
  int r=1;
  uint32_t a, b;
  a=UINT_MAX-1; b=UINT_MAX; EXPECT_FALSE(safe_subx(NULL, sio_u32(a), sio_u32(b)));
  a=0; EXPECT_FALSE(safe_decx(sio_u32(a)));
  a=UINT_MAX; b=UINT_MAX; EXPECT_TRUE(safe_subx(NULL, sio_u32(a), sio_u32(b)));
  a=1; b=100; EXPECT_FALSE(safe_subx(NULL, sio_u32(a), sio_u32(b)));
  a=100; b=0; EXPECT_TRUE(safe_subx(NULL, sio_u32(a), sio_u32(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_u32(a), sio_u32(b)));
  a=0; b=0; EXPECT_TRUE(safe_subx(NULL, sio_u32(a), sio_u32(b)));
  return r;
}

int T_sub_u64() {
  int r=1;
  uint64_t a, b;
  a=SAFE_UINT64_MAX-1; b=SAFE_UINT64_MAX; EXPECT_FALSE(safe_subx(NULL, sio_u64(a), sio_u64(b)));
  a=0; EXPECT_FALSE(safe_decx(sio_u64(a)));
  a=SAFE_UINT64_MAX; b=SAFE_UINT64_MAX; EXPECT_TRUE(safe_subx(NULL, sio_u64(a), sio_u64(b)));
  a=1; b=100; EXPECT_FALSE(safe_subx(NULL, sio_u64(a), sio_u64(b)));
  a=100; b=0; EXPECT_TRUE(safe_subx(NULL, sio_u64(a), sio_u64(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_u64(a), sio_u64(b)));
  a=0; b=0; EXPECT_TRUE(safe_subx(NULL, sio_u64(a), sio_u64(b)));
  return r;
}

int T_sub_ulong() {
  int r=1;
  unsigned long a, b;
  a=ULONG_MAX-1; b=ULONG_MAX; EXPECT_FALSE(safe_subx(NULL, sio_ul(a), sio_ul(b)));
  a=0; EXPECT_FALSE(safe_decx(sio_ul(a)));
  a=ULONG_MAX; b=ULONG_MAX; EXPECT_TRUE(safe_subx(NULL, sio_ul(a), sio_ul(b)));
  a=1; b=100; EXPECT_FALSE(safe_subx(NULL, sio_ul(a), sio_ul(b)));
  a=100; b=0; EXPECT_TRUE(safe_subx(NULL, sio_ul(a), sio_ul(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_ul(a), sio_ul(b)));
  a=0; b=0; EXPECT_TRUE(safe_subx(NULL, sio_ul(a), sio_ul(b)));
  return r;
}

int T_sub_ulonglong() {
  int r=1;
  unsigned long long a, b;
  a=ULLONG_MAX-1; b=ULLONG_MAX; EXPECT_FALSE(safe_subx(NULL, sio_ull(a), sio_ull(b)));
  a=0; EXPECT_FALSE(safe_decx(sio_ull(a)));
  a=ULLONG_MAX; b=ULLONG_MAX; EXPECT_TRUE(safe_subx(NULL, sio_ull(a), sio_ull(b)));
  a=1; b=100; EXPECT_FALSE(safe_subx(NULL, sio_ull(a), sio_ull(b)));
  a=100; b=0; EXPECT_TRUE(safe_subx(NULL, sio_ull(a), sio_ull(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_ull(a), sio_ull(b)));
  a=0; b=0; EXPECT_TRUE(safe_subx(NULL, sio_ull(a), sio_ull(b)));
  return r;
}

int T_sub_sizet() {
  int r=1;
  size_t a, b;
  a=SIZE_MAX-1; b=SIZE_MAX; EXPECT_FALSE(safe_subx(NULL, sio_szt(a), sio_szt(b)));
  a=0; EXPECT_FALSE(safe_decx(sio_szt(a)));
  a=SIZE_MAX; b=SIZE_MAX; EXPECT_TRUE(safe_subx(NULL, sio_szt(a), sio_szt(b)));
  a=1; b=100; EXPECT_FALSE(safe_subx(NULL, sio_szt(a), sio_szt(b)));
  a=100; b=0; EXPECT_TRUE(safe_subx(NULL, sio_szt(a), sio_szt(b)));
  a=10; b=2; EXPECT_TRUE(safe_subx(NULL, sio_szt(a), sio_szt(b)));
  a=0; b=0; EXPECT_TRUE(safe_subx(NULL, sio_szt(a), sio_szt(b)));
  return r;
}

/***** MUL *****/
int T_mul_s8() {
  int r=1;
  int8_t a, b;
  a=SCHAR_MIN; b=-1; EXPECT_FALSE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MIN; b=-2; EXPECT_FALSE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MAX; b=SCHAR_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=-100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=SCHAR_MIN; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=0; b=SCHAR_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=0; b=SCHAR_MIN; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  a=0; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_s8(b)));
  return r;
}

int T_mul_s16() {
  int r=1;
  int16_t a, b;
  a=SHRT_MIN; b=-1; EXPECT_FALSE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MIN; b=-2; EXPECT_FALSE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MAX; b=SHRT_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=-100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=SHRT_MIN; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=0; b=SHRT_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=0; b=SHRT_MIN; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  a=0; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s16(a), sio_s16(b)));
  return r;
}

int T_mul_s32() {
  int r=1;
  int32_t a, b;
  a=INT_MIN; b=-1; EXPECT_FALSE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MIN; b=-2; EXPECT_FALSE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MAX; b=INT_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=-100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=INT_MIN; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=0; b=INT_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=0; b=INT_MIN; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  a=0; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s32(a), sio_s32(b)));
  return r;
}

int T_mul_s64() {
  int r=1;
  int64_t a, b;
  a=SAFE_INT64_MIN; b=-1; EXPECT_FALSE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MIN; b=-2; EXPECT_FALSE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MAX; b=SAFE_INT64_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=-100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=SAFE_INT64_MIN; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=0; b=SAFE_INT64_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=0; b=SAFE_INT64_MIN; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  a=0; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_s64(a), sio_s64(b)));
  return r;
}

int T_mul_long() {
  int r=1;
  long a, b;
  a=LONG_MIN; b=-1; EXPECT_FALSE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MIN; b=-2; EXPECT_FALSE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MAX; b=LONG_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=-100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=LONG_MIN; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=0; b=LONG_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=0; b=LONG_MIN; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  a=0; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sl(a), sio_sl(b)));
  return r;
}
int T_mul_longlong() {
  int r=1;
  long long a, b;
  a=LLONG_MIN; b=-1; EXPECT_FALSE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MIN; b=-2; EXPECT_FALSE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MAX; b=LLONG_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=-100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=LLONG_MIN; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=0; b=LLONG_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=0; b=LLONG_MIN; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  a=0; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sll(a), sio_sll(b)));
  return r;
}
int T_mul_ssizet() {
  int r=1;
  ssize_t a, b;
  a=SSIZE_MIN; b=-1; EXPECT_FALSE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MIN; b=-2; EXPECT_FALSE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MAX; b=SSIZE_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-100; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=SSIZE_MIN; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=0; b=SSIZE_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=0; b=SSIZE_MIN; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  a=0; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_sszt(a), sio_sszt(b)));
  return r;
}

int T_mul_u8() {
  int r=1;
  uint8_t a, b;
  a=UCHAR_MAX-1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=2; b=UCHAR_MAX-1; EXPECT_FALSE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=2; b=UCHAR_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=2; b=UCHAR_MAX/2+1; EXPECT_FALSE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=0; b=UCHAR_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=1; b=UCHAR_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX; b=1; EXPECT_TRUE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_u8(a), sio_u8(b)));
  return r;
}

int T_mul_u16() {
  int r=1;
  uint16_t a, b;
  a=USHRT_MAX-1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=2; b=USHRT_MAX-1; EXPECT_FALSE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=2; b=USHRT_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=2; b=USHRT_MAX/2+1; EXPECT_FALSE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=0; b=USHRT_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=1; b=USHRT_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX; b=1; EXPECT_TRUE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_u16(a), sio_u16(b)));
  return r;
}

int T_mul_u32() {
  int r=1;
  uint32_t a, b;
  a=UINT_MAX-1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=2; b=UINT_MAX-1; EXPECT_FALSE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=UINT_MAX; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=2; b=UINT_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=UINT_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=2; b=UINT_MAX/2+1; EXPECT_FALSE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=UINT_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=0; b=UINT_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=1; b=UINT_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=UINT_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=UINT_MAX; b=1; EXPECT_TRUE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_u32(a), sio_u32(b)));
  return r;
}

int T_mul_u64() {
  int r=1;
  uint64_t a, b;
  a=SAFE_UINT64_MAX-1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=2; b=SAFE_UINT64_MAX-1; EXPECT_FALSE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=SAFE_UINT64_MAX; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=2; b=SAFE_UINT64_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=SAFE_UINT64_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=2; b=SAFE_UINT64_MAX/2+1; EXPECT_FALSE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=SAFE_UINT64_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=0; b=SAFE_UINT64_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=1; b=SAFE_UINT64_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=SAFE_UINT64_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=SAFE_UINT64_MAX; b=1; EXPECT_TRUE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_u64(a), sio_u64(b)));
  return r;
}

int T_mul_ulong() {
  int r=1;
  unsigned long a, b;
  a=ULONG_MAX-1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=2; b=ULONG_MAX-1; EXPECT_FALSE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=ULONG_MAX; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=2; b=ULONG_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=ULONG_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=2; b=ULONG_MAX/2+1; EXPECT_FALSE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=ULONG_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=0; b=ULONG_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=1; b=ULONG_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=ULONG_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=ULONG_MAX; b=1; EXPECT_TRUE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_ul(a), sio_ul(b)));
  return r;
}

int T_mul_ulonglong() {
  int r=1;
  unsigned long long a, b;
  a=ULLONG_MAX-1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=2; b=ULLONG_MAX-1; EXPECT_FALSE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=ULLONG_MAX; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=2; b=ULLONG_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=ULLONG_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=2; b=ULLONG_MAX/2+1; EXPECT_FALSE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=ULLONG_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=0; b=ULLONG_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=1; b=ULLONG_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=ULLONG_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=ULLONG_MAX; b=1; EXPECT_TRUE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_ull(a), sio_ull(b)));
  return r;
}

int T_mul_sizet() {
  int r=1;
  size_t a, b;
  a=SIZE_MAX-1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=2; b=SIZE_MAX-1; EXPECT_FALSE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=SIZE_MAX; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=2; b=SIZE_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=SIZE_MAX/2+1; b=2; EXPECT_FALSE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=2; b=SIZE_MAX/2+1; EXPECT_FALSE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=SIZE_MAX/2; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=0; b=SIZE_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=1; b=SIZE_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=SIZE_MAX; b=0; EXPECT_TRUE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=SIZE_MAX; b=1; EXPECT_TRUE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  a=10; b=2; EXPECT_TRUE(safe_mulx(NULL, sio_szt(a), sio_szt(b)));
  return r;
}

int T_mul_mixed() {
  int r=1;
  int8_t a = 1;
  uint8_t b = 2;
  uint16_t c = 3;
  int32_t d = -10;
  a=1; b=SCHAR_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_u8(b)));
  a=1; b=SCHAR_MAX+1; EXPECT_FALSE(safe_mulx(NULL, sio_s8(a), sio_u8(b)));
  a=0; b=SCHAR_MAX+1; EXPECT_FALSE(safe_mulx(NULL, sio_s8(a), sio_u8(b)));
  a=1; b=SCHAR_MAX-1; EXPECT_TRUE(safe_mulx(NULL, sio_s8(a), sio_u8(b)));
  b=1; c=UCHAR_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_u8(b), sio_u16(c)));
  b=1; c=UCHAR_MAX+1; EXPECT_FALSE(safe_mulx(NULL, sio_u8(b), sio_u16(c)));
  b=0; c=UCHAR_MAX+1; EXPECT_FALSE(safe_mulx(NULL, sio_u8(b), sio_u16(c)));
  b=1; c=UCHAR_MAX-1; EXPECT_TRUE(safe_mulx(NULL, sio_u8(b), sio_u16(c)));
  b=1; c=UCHAR_MAX-1; EXPECT_TRUE(safe_mulx(NULL, sio_u16(c), sio_u8(b)));
  a=1; c=USHRT_MAX; EXPECT_FALSE(safe_mulx(NULL, sio_s8(a), sio_u16(c)));
  b=1; d=-1; EXPECT_FALSE(safe_mulx(NULL, sio_u8(b), sio_s32(d)));
  d=-4, b=UCHAR_MAX; EXPECT_TRUE(safe_mulx(NULL, sio_s32(d), sio_u8(b)));
  //a=1;b=1;c=1; EXPECT_TRUE(safe_mulv(NULL, 3, sio_s8(a), sio_u8(b), sio_u16(c)));
  //a=1;b=1;c=USHRT_MAX-3; EXPECT_FALSE(safe_mulv(NULL, 3, sio_s8(a), sio_u8(b), sio_u16(c)));
  //a=1;b=1;c=SCHAR_MAX-3; EXPECT_TRUE(safe_mulv(NULL, 3, sio_s8(a), sio_u8(b), sio_u16(c)));
  return r;
}


/***** MOD *****/
int T_mod_s8() {
  int r=1;
  int8_t a, b;
  a=SCHAR_MIN; b=-1; EXPECT_FALSE(safe_modx(NULL, sio_s8(a), sio_s8(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_s8(a), sio_s8(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_s8(a), sio_s8(b)));
  a=-100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_s8(a), sio_s8(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_s8(a), sio_s8(b)));
  a=10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_s8(a), sio_s8(b)));
  a=-10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_s8(a), sio_s8(b)));
  return r;
}

int T_mod_s16() {
  int r=1;
  int16_t a, b;
  a=SHRT_MIN; b=-1; EXPECT_FALSE(safe_modx(NULL, sio_s16(a), sio_s16(b)));
  a=-100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_s16(a), sio_s16(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_s16(a), sio_s16(b)));
  a=10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_s16(a), sio_s16(b)));
  a=-10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_s16(a), sio_s16(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_s16(a), sio_s16(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_s16(a), sio_s16(b)));
  return r;
}

int T_mod_s32() {
  int r=1;
  int32_t a, b;
  a=INT_MIN; b=-1; EXPECT_FALSE(safe_modx(NULL, sio_s32(a), sio_s32(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_s32(a), sio_s32(b)));
  a=-100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_s32(a), sio_s32(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_s32(a), sio_s32(b)));
  a=10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_s32(a), sio_s32(b)));
  a=-10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_s32(a), sio_s32(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_s32(a), sio_s32(b)));
  return r;
}

int T_mod_s64() {
  int r=1;
  int64_t a, b;
  a=SAFE_INT64_MIN; b=-1; EXPECT_FALSE(safe_modx(NULL, sio_s64(a), sio_s64(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_s64(a), sio_s64(b)));
  a=-100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_s64(a), sio_s64(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_s64(a), sio_s64(b)));
  a=10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_s64(a), sio_s64(b)));
  a=-10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_s64(a), sio_s64(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_s64(a), sio_s64(b)));
  return r;
}

int T_mod_long() {
  int r=1;
  long a, b;
  a=LONG_MIN; b=-1; EXPECT_FALSE(safe_modx(NULL, sio_sl(a), sio_sl(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_sl(a), sio_sl(b)));
  a=-100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_sl(a), sio_sl(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_sl(a), sio_sl(b)));
  a=10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_sl(a), sio_sl(b)));
  a=-10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_sl(a), sio_sl(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_sl(a), sio_sl(b)));
  return r;
}
int T_mod_longlong() {
  int r=1;
  long long a, b;
  a=LLONG_MIN; b=-1LL; EXPECT_FALSE(safe_modx(NULL, sio_sll(a), sio_sll(b)));
  a=100LL; b=0LL; EXPECT_FALSE(safe_modx(NULL, sio_sll(a), sio_sll(b)));
  a=-100LL; b=0LL; EXPECT_FALSE(safe_modx(NULL, sio_sll(a), sio_sll(b)));
  a=-10LL; b=-2LL; EXPECT_TRUE(safe_modx(NULL, sio_sll(a), sio_sll(b)));
  a=10LL; b=-2LL; EXPECT_TRUE(safe_modx(NULL, sio_sll(a), sio_sll(b)));
  a=-10LL; b=2LL; EXPECT_TRUE(safe_modx(NULL, sio_sll(a), sio_sll(b)));
  a=10LL; b=2LL; EXPECT_TRUE(safe_modx(NULL, sio_sll(a), sio_sll(b)));
  return r;
}
int T_mod_ssizet() {
  int r=1;
  ssize_t a, b;
  a=SSIZE_MIN; b=-1; EXPECT_FALSE(safe_modx(NULL, sio_sszt(a), sio_sszt(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_sszt(a), sio_sszt(b)));
  a=10; b=-2; EXPECT_TRUE(safe_modx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_sszt(a), sio_sszt(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_sszt(a), sio_sszt(b)));
  return r;
}

int T_mod_u8() {
  int r=1;
  uint8_t a, b;
  a=0; b=UCHAR_MAX; EXPECT_TRUE(safe_modx(NULL, sio_u8(a), sio_u8(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_u8(a), sio_u8(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_u8(a), sio_u8(b)));
  return r;
}

int T_mod_u16() {
  int r=1;
  uint16_t a, b;
  a=0; b=USHRT_MAX; EXPECT_TRUE(safe_modx(NULL, sio_u16(a), sio_u16(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_u16(a), sio_u16(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_u16(a), sio_u16(b)));
  return r;
}

int T_mod_u32() {
  int r=1;
  uint32_t a, b;
  a=0; b=UINT_MAX; EXPECT_TRUE(safe_modx(NULL, sio_u32(a), sio_u32(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_u32(a), sio_u32(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_u32(a), sio_u32(b)));
  return r;
}

int T_mod_u64() {
  int r=1;
  uint64_t a, b;
  a=0; b=SAFE_INT64_MAX; EXPECT_TRUE(safe_modx(NULL, sio_u64(a), sio_u64(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_u64(a), sio_u64(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_u64(a), sio_u64(b)));
  return r;
}

int T_mod_ulong() {
  int r=1;
  unsigned long a, b;
  a=0; b=LONG_MAX; EXPECT_TRUE(safe_modx(NULL, sio_ul(a), sio_ul(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_ul(a), sio_ul(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_ul(a), sio_ul(b)));
  return r;
}

int T_mod_ulonglong() {
  int r=1;
  unsigned long long a, b;
  a=0ULL; b=~0ULL; EXPECT_TRUE(safe_modx(NULL, sio_ull(a), sio_ull(b)));
  a=100ULL; b=0ULL; EXPECT_FALSE(safe_modx(NULL, sio_ull(a), sio_ull(b)));
  a=10ULL; b=2ULL; EXPECT_TRUE(safe_modx(NULL, sio_ull(a), sio_ull(b)));
  return r;
}

int T_mod_sizet() {
  int r=1;
  size_t a, b;
  a=0; b=SIZE_MAX; EXPECT_TRUE(safe_modx(NULL, sio_szt(a), sio_szt(b)));
  a=100; b=0; EXPECT_FALSE(safe_modx(NULL, sio_szt(a), sio_szt(b)));
  a=10; b=2; EXPECT_TRUE(safe_modx(NULL, sio_szt(a), sio_szt(b)));
  return r;
}

/***** DIV *****/
int T_div_s8() {
  int r=1;
  int8_t a, b;
  a=SCHAR_MIN; b=-1; EXPECT_FALSE(safe_divx(NULL, sio_s8(a), sio_s8(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_s8(a), sio_s8(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s8(a), sio_s8(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s8(a), sio_s8(b)));
  a=-100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_s8(a), sio_s8(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_s8(a), sio_s8(b)));
  a=10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_s8(a), sio_s8(b)));
  a=-10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s8(a), sio_s8(b)));
  return r;
}

int T_div_s16() {
  int r=1;
  int16_t a, b;
  a=SHRT_MIN; b=-1; EXPECT_FALSE(safe_divx(NULL, sio_s16(a), sio_s16(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_s16(a), sio_s16(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s16(a), sio_s16(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s16(a), sio_s16(b)));
  a=-100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_s16(a), sio_s16(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_s16(a), sio_s16(b)));
  a=10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_s16(a), sio_s16(b)));
  a=-10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s16(a), sio_s16(b)));
  return r;
}

int T_div_s32() {
  int r=1;
  int32_t a, b;
  a=INT_MIN; b=-1; EXPECT_FALSE(safe_divx(NULL, sio_s32(a), sio_s32(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_s32(a), sio_s32(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s32(a), sio_s32(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s32(a), sio_s32(b)));
  a=-100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_s32(a), sio_s32(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_s32(a), sio_s32(b)));
  a=10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_s32(a), sio_s32(b)));
  a=-10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s32(a), sio_s32(b)));
  return r;
}

int T_div_s64() {
  int r=1;
  int64_t a, b;
  a=SAFE_INT64_MIN; b=-1; EXPECT_FALSE(safe_divx(NULL, sio_s64(a), sio_s64(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_s64(a), sio_s64(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s64(a), sio_s64(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s64(a), sio_s64(b)));
  a=-100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_s64(a), sio_s64(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_s64(a), sio_s64(b)));
  a=10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_s64(a), sio_s64(b)));
  a=-10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_s64(a), sio_s64(b)));
  return r;
}

int T_div_long() {
  int r=1;
  long a, b;
  a=LONG_MIN; b=-1; EXPECT_FALSE(safe_divx(NULL, sio_sl(a), sio_sl(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_sl(a), sio_sl(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_sl(a), sio_sl(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_sl(a), sio_sl(b)));
  a=-100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_sl(a), sio_sl(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_sl(a), sio_sl(b)));
  a=10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_sl(a), sio_sl(b)));
  a=-10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_sl(a), sio_sl(b)));
  return r;
}
int T_div_longlong() {
  int r=1;
  long long a, b;
  a=LLONG_MIN; b=-1LL; EXPECT_FALSE(safe_divx(NULL, sio_sll(a), sio_sll(b)));
  a=100LL; b=0LL; EXPECT_FALSE(safe_divx(NULL, sio_sll(a), sio_sll(b)));
  a=10LL; b=2LL; EXPECT_TRUE(safe_divx(NULL, sio_sll(a), sio_sll(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_sll(a), sio_sll(b)));
  a=-100LL; b=0LL; EXPECT_FALSE(safe_divx(NULL, sio_sll(a), sio_sll(b)));
  a=-10LL; b=-2LL; EXPECT_TRUE(safe_divx(NULL, sio_sll(a), sio_sll(b)));
  a=10LL; b=-2LL; EXPECT_TRUE(safe_divx(NULL, sio_sll(a), sio_sll(b)));
  a=-10LL; b=2LL; EXPECT_TRUE(safe_divx(NULL, sio_sll(a), sio_sll(b)));
  return r;
}
int T_div_ssizet() {
  int r=1;
  ssize_t a, b;
  a=SSIZE_MIN; b=-1; EXPECT_FALSE(safe_divx(NULL, sio_sszt(a), sio_sszt(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_sszt(a), sio_sszt(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_sszt(a), sio_sszt(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_sszt(a), sio_sszt(b)));
  a=10; b=-2; EXPECT_TRUE(safe_divx(NULL, sio_sszt(a), sio_sszt(b)));
  a=-10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_sszt(a), sio_sszt(b)));
  return r;
}

int T_div_u8() {
  int r=1;
  uint8_t a, b;
  a=0; b=UCHAR_MAX; EXPECT_TRUE(safe_divx(NULL, sio_u8(a), sio_u8(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_u8(a), sio_u8(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_u8(a), sio_u8(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_u8(a), sio_u8(b)));
  return r;
}

int T_div_u16() {
  int r=1;
  uint16_t a, b;
  a=0; b=USHRT_MAX; EXPECT_TRUE(safe_divx(NULL, sio_u16(a), sio_u16(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_u16(a), sio_u16(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_u16(a), sio_u16(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_u16(a), sio_u16(b)));
  return r;
}

int T_div_u32() {
  int r=1;
  uint32_t a, b;
  a=0; b=UINT_MAX; EXPECT_TRUE(safe_divx(NULL, sio_u32(a), sio_u32(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_u32(a), sio_u32(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_u32(a), sio_u32(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_u32(a), sio_u32(b)));
  return r;
}

int T_div_u64() {
  int r=1;
  uint64_t a, b;
  a=0; b=SAFE_INT64_MAX; EXPECT_TRUE(safe_divx(NULL, sio_u64(a), sio_u64(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_u64(a), sio_u64(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_u64(a), sio_u64(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_u64(a), sio_u64(b)));
  return r;
}

int T_div_ulong() {
  int r=1;
  unsigned long a, b;
  a=0; b=LONG_MAX; EXPECT_TRUE(safe_divx(NULL, sio_ul(a), sio_ul(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_ul(a), sio_ul(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_ul(a), sio_ul(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_ul(a), sio_ul(b)));
  return r;
}

int T_div_ulonglong() {
  int r=1;
  unsigned long long a, b;
  a=0ULL; b=~0ULL; EXPECT_TRUE(safe_divx(NULL, sio_ull(a), sio_ull(b)));
  a=100ULL; b=0ULL; EXPECT_FALSE(safe_divx(NULL, sio_ull(a), sio_ull(b)));
  a=10ULL; b=2ULL; EXPECT_TRUE(safe_divx(NULL, sio_ull(a), sio_ull(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_ull(a), sio_ull(b)));
  return r;
}

int T_div_sizet() {
  int r=1;
  size_t a, b;
  a=0; b=SIZE_MAX; EXPECT_TRUE(safe_divx(NULL, sio_szt(a), sio_szt(b)));
  a=100; b=0; EXPECT_FALSE(safe_divx(NULL, sio_szt(a), sio_szt(b)));
  a=10; b=2; EXPECT_TRUE(safe_divx(NULL, sio_szt(a), sio_szt(b)));
  a=0; b=2; EXPECT_TRUE(safe_divx(NULL, sio_szt(a), sio_szt(b)));
  return r;
}


int T_div_mixed() {
  int r=1;
  uint8_t u8;
  int16_t a;
  uint64_t b;
  a=8; b=8; EXPECT_TRUE(safe_divx(NULL, sio_s16(a), sio_u64(b)));
  u8=8; b=8; EXPECT_TRUE(safe_divx(NULL, sio_u8(u8), sio_u64(b)));
  return r;
}

/***** SHL *****/
int T_shl_s8() {
  int r=1;
  int8_t a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shlx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=sizeof(int8_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=sizeof(int8_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s8(a), sio_s8(b)));
  a=5; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s8(a), sio_s8(b)));
  return r;
}

int T_shl_s16() {
  int r=1;
  int16_t a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shlx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=sizeof(int16_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=sizeof(int16_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s16(a), sio_s16(b)));
  a=100; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s16(a), sio_s16(b)));
  return r;
}

int T_shl_s32() {
  int r=1;
  int32_t a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shlx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=sizeof(int32_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=sizeof(int32_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s32(a), sio_s32(b)));
  a=100; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s32(a), sio_s32(b)));
  return r;
}

int T_shl_s64() {
  int r=1;
  int64_t a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shlx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=sizeof(int64_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=sizeof(int64_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s64(a), sio_s64(b)));
  a=100; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_s64(a), sio_s64(b)));
  return r;
}

int T_shl_long() {
  int r=1;
  long a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shlx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=sizeof(long)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=sizeof(long)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_sl(a), sio_sl(b)));
  a=100; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_sl(a), sio_sl(b)));
  return r;
}
int T_shl_longlong() {
  int r=1;
  long long a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shlx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=sizeof(long long)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=sizeof(long long)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_sll(a), sio_sll(b)));
  a=100; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_sll(a), sio_sll(b)));
  return r;
}

int T_shl_ssizet() {
  int r=1;
  ssize_t a, b;
   a=-1; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shlx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=sizeof(ssize_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=sizeof(ssize_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shlx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_sszt(a), sio_sszt(b)));
  a=100; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_sszt(a), sio_sszt(b)));
 return r;
}

int T_shl_u8() {
  int r=1;
  uint8_t a, b;
  a=1; b=sizeof(uint8_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shlx(NULL, sio_u8(a), sio_u8(b)));
  a=4; b=sizeof(uint8_t)*CHAR_BIT; EXPECT_FALSE(safe_shlx(NULL, sio_u8(a), sio_u8(b)));
  a=UCHAR_MAX; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_u8(a), sio_u8(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_u8(a), sio_u8(b)));
  a=1; b=4; EXPECT_TRUE(safe_shlx(NULL, sio_u8(a), sio_u8(b)));
  return r;
}

int T_shl_u16() {
  int r=1;
  uint16_t a, b;
  a=1; b=sizeof(uint16_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shlx(NULL, sio_u16(a), sio_u16(b)));
  a=4; b=sizeof(uint16_t)*CHAR_BIT; EXPECT_FALSE(safe_shlx(NULL, sio_u16(a), sio_u16(b)));
  a=USHRT_MAX; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_u16(a), sio_u16(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_u16(a), sio_u16(b)));
  a=1; b=4; EXPECT_TRUE(safe_shlx(NULL, sio_u16(a), sio_u16(b)));
  return r;
}

int T_shl_u32() {
  int r=1;
  uint32_t a, b;
  a=1; b=sizeof(uint32_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shlx(NULL, sio_u32(a), sio_u32(b)));
  a=4; b=sizeof(uint32_t)*CHAR_BIT; EXPECT_FALSE(safe_shlx(NULL, sio_u32(a), sio_u32(b)));
  a=UINT_MAX; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_u32(a), sio_u32(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_u32(a), sio_u32(b)));
  a=1; b=4; EXPECT_TRUE(safe_shlx(NULL, sio_u32(a), sio_u32(b)));
  return r;
}

int T_shl_u64() {
  int r=1;
  uint64_t a, b;
  a=1; b=sizeof(uint64_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shlx(NULL, sio_u64(a), sio_u64(b)));
  a=4; b=sizeof(uint64_t)*CHAR_BIT; EXPECT_FALSE(safe_shlx(NULL, sio_u64(a), sio_u64(b)));
  a=SAFE_UINT64_MAX; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_u64(a), sio_u64(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_u64(a), sio_u64(b)));
  a=1; b=4; EXPECT_TRUE(safe_shlx(NULL, sio_u64(a), sio_u64(b)));
  return r;
}

int T_shl_ulong() {
  int r=1;
  unsigned long a, b;
  a=1; b=sizeof(unsigned long)*CHAR_BIT+1; EXPECT_FALSE(safe_shlx(NULL, sio_ul(a), sio_ul(b)));
  a=4; b=sizeof(unsigned long)*CHAR_BIT; EXPECT_FALSE(safe_shlx(NULL, sio_ul(a), sio_ul(b)));
  a=ULONG_MAX; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_ul(a), sio_ul(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_ul(a), sio_ul(b)));
  a=1; b=4; EXPECT_TRUE(safe_shlx(NULL, sio_ul(a), sio_ul(b)));
  return r;
}

int T_shl_ulonglong() {
  int r=1;
  unsigned long long a, b;
  a=1; b=sizeof(unsigned long long)*CHAR_BIT+1; EXPECT_FALSE(safe_shlx(NULL, sio_ull(a), sio_ull(b)));
  a=4; b=sizeof(unsigned long long)*CHAR_BIT; EXPECT_FALSE(safe_shlx(NULL, sio_ull(a), sio_ull(b)));
  a=ULLONG_MAX; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_ull(a), sio_ull(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_ull(a), sio_ull(b)));
  a=1; b=4; EXPECT_TRUE(safe_shlx(NULL, sio_ull(a), sio_ull(b)));
  return r;
}

int T_shl_sizet() {
  int r=1;
  size_t a, b;
  a=1; b=sizeof(size_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shlx(NULL, sio_szt(a), sio_szt(b)));
  a=4; b=sizeof(size_t)*CHAR_BIT; EXPECT_FALSE(safe_shlx(NULL, sio_szt(a), sio_szt(b)));
  a=SIZE_MAX; b=1; EXPECT_FALSE(safe_shlx(NULL, sio_szt(a), sio_szt(b)));
  a=1; b=2; EXPECT_TRUE(safe_shlx(NULL, sio_szt(a), sio_szt(b)));
  a=1; b=4; EXPECT_TRUE(safe_shlx(NULL, sio_szt(a), sio_szt(b)));
  return r;
}

/***** SHR *****/
int T_shr_s8() {
  int r=1;
  int8_t a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shrx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shrx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=sizeof(int8_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=sizeof(int8_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s8(a), sio_s8(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s8(a), sio_s8(b)));
  a=5; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s8(a), sio_s8(b)));
  return r;
}

int T_shr_s16() {
  int r=1;
  int16_t a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shrx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shrx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=sizeof(int16_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=sizeof(int16_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s16(a), sio_s16(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s16(a), sio_s16(b)));
  a=100; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s16(a), sio_s16(b)));
  return r;
}

int T_shr_s32() {
  int r=1;
  int32_t a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shrx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shrx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=sizeof(int32_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=sizeof(int32_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s32(a), sio_s32(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s32(a), sio_s32(b)));
  a=100; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s32(a), sio_s32(b)));
  return r;
}

int T_shr_s64() {
  int r=1;
  int64_t a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shrx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shrx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=sizeof(int64_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=sizeof(int64_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s64(a), sio_s64(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s64(a), sio_s64(b)));
  a=100; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_s64(a), sio_s64(b)));
  return r;
}

int T_shr_long() {
  int r=1;
  long a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shrx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shrx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=sizeof(long)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=sizeof(long)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_sl(a), sio_sl(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_sl(a), sio_sl(b)));
  a=100; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_sl(a), sio_sl(b)));
  return r;
}
int T_shr_longlong() {
  int r=1;
  long long a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shrx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shrx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=sizeof(long long)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=sizeof(long long)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_sll(a), sio_sll(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_sll(a), sio_sll(b)));
  a=100; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_sll(a), sio_sll(b)));
  return r;
}
int T_shr_ssizet() {
  int r=1;
  ssize_t a, b;
  a=-1; b=1; EXPECT_FALSE(safe_shrx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=-1; EXPECT_FALSE(safe_shrx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=sizeof(ssize_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=sizeof(ssize_t)*CHAR_BIT + 1; EXPECT_FALSE(safe_shrx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_sszt(a), sio_sszt(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_sszt(a), sio_sszt(b)));
  a=100; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_sszt(a), sio_sszt(b)));
 return r;
}

int T_shr_u8() {
  int r=1;
  uint8_t a, b;
  a=1; b=sizeof(uint8_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shrx(NULL, sio_u8(a), sio_u8(b)));
  a=4; b=sizeof(uint8_t)*CHAR_BIT; EXPECT_FALSE(safe_shrx(NULL, sio_u8(a), sio_u8(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_u8(a), sio_u8(b)));
  a=1; b=4; EXPECT_TRUE(safe_shrx(NULL, sio_u8(a), sio_u8(b)));
  return r;
}

int T_shr_u16() {
  int r=1;
  uint16_t a, b;
  a=1; b=sizeof(uint16_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shrx(NULL, sio_u16(a), sio_u16(b)));
  a=4; b=sizeof(uint16_t)*CHAR_BIT; EXPECT_FALSE(safe_shrx(NULL, sio_u16(a), sio_u16(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_u16(a), sio_u16(b)));
  a=1; b=4; EXPECT_TRUE(safe_shrx(NULL, sio_u16(a), sio_u16(b)));
  return r;
}

int T_shr_u32() {
  int r=1;
  uint32_t a, b;
  a=1; b=sizeof(uint32_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shrx(NULL, sio_u32(a), sio_u32(b)));
  a=4; b=sizeof(uint32_t)*CHAR_BIT; EXPECT_FALSE(safe_shrx(NULL, sio_u32(a), sio_u32(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_u32(a), sio_u32(b)));
  a=1; b=4; EXPECT_TRUE(safe_shrx(NULL, sio_u32(a), sio_u32(b)));
  return r;
}

int T_shr_u64() {
  int r=1;
  uint64_t a, b;
  a=1; b=sizeof(uint64_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shrx(NULL, sio_u64(a), sio_u64(b)));
  a=4; b=sizeof(uint64_t)*CHAR_BIT; EXPECT_FALSE(safe_shrx(NULL, sio_u64(a), sio_u64(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_u64(a), sio_u64(b)));
  a=1; b=4; EXPECT_TRUE(safe_shrx(NULL, sio_u64(a), sio_u64(b)));
  return r;
}

int T_shr_ulong() {
  int r=1;
  unsigned long a, b;
  a=1; b=sizeof(unsigned long)*CHAR_BIT+1; EXPECT_FALSE(safe_shrx(NULL, sio_ul(a), sio_ul(b)));
  a=4; b=sizeof(unsigned long)*CHAR_BIT; EXPECT_FALSE(safe_shrx(NULL, sio_ul(a), sio_ul(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_ul(a), sio_ul(b)));
  a=1; b=4; EXPECT_TRUE(safe_shrx(NULL, sio_ul(a), sio_ul(b)));
  return r;
}

int T_shr_ulonglong() {
  int r=1;
  unsigned long long a, b;
  a=1; b=sizeof(unsigned long long)*CHAR_BIT+1; EXPECT_FALSE(safe_shrx(NULL, sio_ull(a), sio_ull(b)));
  a=4; b=sizeof(unsigned long long)*CHAR_BIT; EXPECT_FALSE(safe_shrx(NULL, sio_ull(a), sio_ull(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_ull(a), sio_ull(b)));
  a=1; b=4; EXPECT_TRUE(safe_shrx(NULL, sio_ull(a), sio_ull(b)));
  return r;
}

int T_shr_sizet() {
  int r=1;
  size_t a, b;
  a=1; b=sizeof(size_t)*CHAR_BIT+1; EXPECT_FALSE(safe_shrx(NULL, sio_szt(a), sio_szt(b)));
  a=4; b=sizeof(size_t)*CHAR_BIT; EXPECT_FALSE(safe_shrx(NULL, sio_szt(a), sio_szt(b)));
  a=1; b=2; EXPECT_TRUE(safe_shrx(NULL, sio_szt(a), sio_szt(b)));
  a=1; b=4; EXPECT_TRUE(safe_shrx(NULL, sio_szt(a), sio_szt(b)));
  return r;
}

/***** SAFE_IOPF *****/

int T_iopf_null() {
  int r=1;
  EXPECT_TRUE(safe_iopf(NULL, "+", 1, 1));
  return r;
}

/* Ensure that arguments can also be targets */
int T_iopf_self() {
  int r=1;
  int a = 10, b = 20, c = 30;
  EXPECT_TRUE(safe_iopf(&a, "+", a, b));
  EXPECT_EQUAL(a, 30);
  a = 10, b = 20;
  EXPECT_TRUE(safe_iopf(&b, "+", a, b));
  EXPECT_EQUAL(b, 30);
  a = 30, b = 20, c = 10;
  EXPECT_TRUE(safe_iopf(&c, "++", a, b, c));
  EXPECT_EQUAL(c, 60);
  return r;
}


/*** IOPF ADD ***/

int T_iopf_add_u8u8() {
  int r=1;
  uint8_t a, b, c;
  a=10 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "u8+u8", a, b));
                     EXPECT_EQUAL(c, 20);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u8+u8", a, b));
                   EXPECT_EQUAL(c, 0);
  a=UCHAR_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "u8+u8", a, b));
                           EXPECT_EQUAL(c, UCHAR_MAX);
  a=UCHAR_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "u8+u8", a, b));
                         EXPECT_EQUAL(c, 0);
  a=UCHAR_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "u8+u8", b, a));
                           EXPECT_EQUAL(c, UCHAR_MAX);
  a=UCHAR_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "u8+u8", b, a));
                         EXPECT_EQUAL(c, 0);

  return r;
}

int T_iopf_add_u16u16() {
  int r=1;
  uint16_t a, b, c;
  a=10 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "u16+u16", a, b));
                     EXPECT_EQUAL(c, 20);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u16+u16", a, b));
                   EXPECT_EQUAL(c, 0);
  a=USHRT_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "u16+u16", a, b));
                           EXPECT_EQUAL(c, USHRT_MAX);
  a=USHRT_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "u16+u16", a, b));
                         EXPECT_EQUAL(c, 0);
  return r;
}

int T_iopf_add_u32u32() {
  int r=1;
  uint32_t a, b, c;
  a=10 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "u32+u32", a, b));
                     EXPECT_EQUAL(c, 20);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u32+u32", a, b));
                   EXPECT_EQUAL(c, 0);
  a=UINT_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "u32+u32", a, b));
                          EXPECT_EQUAL(c, UINT_MAX);
  a=UINT_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "u32+u32", a, b));
                        EXPECT_EQUAL(c, 0);
  return r;
}

int T_iopf_add_u64u64() {
  int r=1;
  uint64_t a, b, c;
  a=10 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "u64+u64", a, b));
                     EXPECT_EQUAL(c, 20);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u64+u64", a, b));
                   EXPECT_EQUAL(c, 0);
  a=SAFE_UINT64_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "u64+u64", a, b));
                                 EXPECT_EQUAL(c, SAFE_UINT64_MAX);
  a=SAFE_UINT64_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "u64+u64", a, b));
                               EXPECT_EQUAL(c, 0);
  return r;
}

int T_iopf_add_s8s8() {
  int r=1;
  int8_t a, b, c;
  a=10 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "s8+s8", a, b));
                     EXPECT_EQUAL(c, 20);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s8+s8", a, b));
                   EXPECT_EQUAL(c, 0);
  a=SCHAR_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "s8+s8", a, b));
                           EXPECT_EQUAL(c, SCHAR_MAX);
  a=SCHAR_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "s8+s8", a, b));
                         EXPECT_EQUAL(c, 0);
  a=SCHAR_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "s8+s8", b, a));
                           EXPECT_EQUAL(c, SCHAR_MAX);
  a=SCHAR_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "s8+s8", b, a));
                         EXPECT_EQUAL(c, 0);
  a=SCHAR_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s8+s8", a, b));
                            EXPECT_EQUAL(c, SCHAR_MIN);
  a=SCHAR_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s8+s8", a, b));
                          EXPECT_EQUAL(c, 0);
  a=SCHAR_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s8+s8", b, a));
                            EXPECT_EQUAL(c, SCHAR_MIN);
  a=SCHAR_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s8+s8", b, a));
                          EXPECT_EQUAL(c, 0);
  return r;
}

int T_iopf_add_s16s16() {
  int r=1;
  int16_t a, b, c;
  a=10 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "s16+s16", a, b));
                     EXPECT_EQUAL(c, 20);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s16+s16", a, b));
                   EXPECT_EQUAL(c, 0);
  a=SHRT_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "s16+s16", a, b));
                           EXPECT_EQUAL(c, SHRT_MAX);
  a=SHRT_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "s16+s16", a, b));
                        EXPECT_EQUAL(c, 0);
  a=SHRT_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "s16+s16", b, a));
                          EXPECT_EQUAL(c, SHRT_MAX);
  a=SHRT_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "s16+s16", b, a));
                        EXPECT_EQUAL(c, 0);
  a=SHRT_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s16+s16", a, b));
                           EXPECT_EQUAL(c, SHRT_MIN);
  a=SHRT_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s16+s16", a, b));
                         EXPECT_EQUAL(c, 0);
  a=SHRT_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s16+s16", b, a));
                           EXPECT_EQUAL(c, SHRT_MIN);
  a=SHRT_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s16+s16", b, a));
                         EXPECT_EQUAL(c, 0);
  return r;
}


int T_iopf_add_s32s32() {
  int r=1;
  int32_t a, b, c;
  a=10 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "s32+s32", a, b));
                     EXPECT_EQUAL(c, 20);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s32+s32", a, b));
                   EXPECT_EQUAL(c, 0);
  a=INT_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "s32+s32", a, b));
                           EXPECT_EQUAL(c, INT_MAX);
  a=INT_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "s32+s32", a, b));
                        EXPECT_EQUAL(c, 0);
  a=INT_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "s32+s32", b, a));
                          EXPECT_EQUAL(c, INT_MAX);
  a=INT_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "s32+s32", b, a));
                        EXPECT_EQUAL(c, 0);
  a=INT_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s32+s32", a, b));
                           EXPECT_EQUAL(c, INT_MIN);
  a=INT_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s32+s32", a, b));
                         EXPECT_EQUAL(c, 0);
  a=INT_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s32+s32", b, a));
                           EXPECT_EQUAL(c, INT_MIN);
  a=INT_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s32+s32", b, a));
                         EXPECT_EQUAL(c, 0);
  return r;
}


int T_iopf_add_s64s64() {
  int r=1;
  int64_t a, b, c;
  a=10 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "s64+s64", a, b));
                     EXPECT_EQUAL(c, 20);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s64+s64", a, b));
                   EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "s64+s64", a, b));
                           EXPECT_EQUAL(c, SAFE_INT64_MAX);
  a=SAFE_INT64_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "s64+s64", a, b));
                        EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MAX-1, b=1, c=0; EXPECT_TRUE(safe_iopf(&c, "s64+s64", b, a));
                          EXPECT_EQUAL(c, SAFE_INT64_MAX);
  a=SAFE_INT64_MAX, b=1, c=0; EXPECT_FALSE(safe_iopf(&c, "s64+s64", b, a));
                        EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s64+s64", a, b));
                           EXPECT_EQUAL(c, SAFE_INT64_MIN);
  a=SAFE_INT64_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s64+s64", a, b));
                         EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s64+s64", b, a));
                           EXPECT_EQUAL(c, SAFE_INT64_MIN);
  a=SAFE_INT64_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s64+s64", b, a));
                         EXPECT_EQUAL(c, 0);
  return r;
}

/*** IOPF MUL ***/
int T_iopf_mul_u8u8() {
  int r=1;
  uint8_t a, b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "u8*u8", a, b));
                     EXPECT_EQUAL(c, 100);
  a=10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u8*u8", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "u8*u8", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u8*u8", a, b));
                   EXPECT_EQUAL(c, 0);
  a=UCHAR_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "u8*u8", a, b));
                           EXPECT_EQUAL(c, UCHAR_MAX/2*2);
  a=UCHAR_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "u8*u8", a, b));
                             EXPECT_EQUAL(c, 0);
  a=UCHAR_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "u8*u8", a, b));
                             EXPECT_EQUAL(c, 0);
  a=UCHAR_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "u8*u8", b, a));
                           EXPECT_EQUAL(c, UCHAR_MAX/2*2);
  a=UCHAR_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "u8*u8", b, a));
                             EXPECT_EQUAL(c, 0);
  a=UCHAR_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "u8*u8", b, a));
                             EXPECT_EQUAL(c, 0);
  return r;
}

int T_iopf_mul_u16u16() {
  int r=1;
  uint16_t a, b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "u16*u16", a, b));
                     EXPECT_EQUAL(c, 100);
  a=10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u16*u16", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "u16*u16", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u16*u16", a, b));
                   EXPECT_EQUAL(c, 0);
  a=USHRT_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "u16*u16", a, b));
                           EXPECT_EQUAL(c, USHRT_MAX/2*2);
  a=USHRT_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "u16*u16", a, b));
                             EXPECT_EQUAL(c, 0);
  a=USHRT_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "u16*u16", a, b));
                             EXPECT_EQUAL(c, 0);
  a=USHRT_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "u16*u16", b, a));
                           EXPECT_EQUAL(c, USHRT_MAX/2*2);
  a=USHRT_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "u16*u16", b, a));
                             EXPECT_EQUAL(c, 0);
  a=USHRT_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "u16*u16", b, a));
                             EXPECT_EQUAL(c, 0);
  return r;
}

int T_iopf_mul_u32u32() {
  int r=1;
  uint32_t a, b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "u32*u32", a, b));
                     EXPECT_EQUAL(c, 100);
  a=10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u32*u32", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "u32*u32", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u32*u32", a, b));
                   EXPECT_EQUAL(c, 0);
  a=UINT_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "u32*u32", a, b));
                           EXPECT_EQUAL(c, UINT_MAX/2*2);
  a=UINT_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "u32*u32", a, b));
                             EXPECT_EQUAL(c, 0);
  a=UINT_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "u32*u32", a, b));
                             EXPECT_EQUAL(c, 0);
  a=UINT_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "u32*u32", b, a));
                           EXPECT_EQUAL(c, UINT_MAX/2*2);
  a=UINT_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "u32*u32", b, a));
                             EXPECT_EQUAL(c, 0);
  a=UINT_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "u32*u32", b, a));
                             EXPECT_EQUAL(c, 0);
  return r;
}

int T_iopf_mul_u32u32u32() {
  int r=1;
  uint32_t a, b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "u32*u32*u32", a, b, c));
                     EXPECT_EQUAL(c, 1000);
  a=10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u32*u32*u32", a, b, c));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "u32*u32*u32", a, b, c));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u32*u32*u32", a, b, c));
                   EXPECT_EQUAL(c, 0);
  a=UINT_MAX/2, b=2, c=1; EXPECT_TRUE(safe_iopf(&c, "u32*u32*u32", a, b, c));
                          EXPECT_EQUAL(c, UINT_MAX/2*2);
  /* This should fail before the 0 can be considered */
  a=UINT_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "u32*u32*u32", a, b, c));
                            EXPECT_EQUAL(c, 0);
  /* The most common case: w*h*d */
  a=1000, b=1000, c=8; EXPECT_TRUE(safe_iopf(&c, "u32*u32*u32", a, b, c));
                          EXPECT_EQUAL(c, 8000000);
  return r;
}



int T_iopf_mul_u64u64() {
  int r=1;
  uint64_t a, b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "u64*u64", a, b));
                     EXPECT_EQUAL(c, 100);
  a=10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u64*u64", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "u64*u64", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "u64*u64", a, b));
                   EXPECT_EQUAL(c, 0);
  a=SAFE_UINT64_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "u64*u64", a, b));
                           EXPECT_EQUAL(c, SAFE_UINT64_MAX/2*2);
  a=SAFE_UINT64_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "u64*u64", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_UINT64_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "u64*u64", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_UINT64_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "u64*u64", b, a));
                           EXPECT_EQUAL(c, SAFE_UINT64_MAX/2*2);
  a=SAFE_UINT64_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "u64*u64", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_UINT64_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "u64*u64", b, a));
                             EXPECT_EQUAL(c, 0);
  return r;
}

int T_iopf_mul_s8s8() {
  int r=1;
  int8_t a, b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                     EXPECT_EQUAL(c, 100);
  a=-10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                     EXPECT_EQUAL(c, -100);
  a=10 ,b=-10, c=10; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                     EXPECT_EQUAL(c, -100);
  a=10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                    EXPECT_EQUAL(c, 0);
  a=-10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                     EXPECT_EQUAL(c, 0);
  a=0 ,b=-10, c=100; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                     EXPECT_EQUAL(c, 0);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                   EXPECT_EQUAL(c, 0);
  a=SCHAR_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                           EXPECT_EQUAL(c, SCHAR_MAX/2*2);
  a=SCHAR_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s8*s8", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SCHAR_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s8*s8", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SCHAR_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s8*s8", b, a));
                           EXPECT_EQUAL(c, SCHAR_MAX/2*2);
  a=SCHAR_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s8*s8", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SCHAR_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s8*s8", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SCHAR_MIN/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                           EXPECT_EQUAL(c, SCHAR_MIN);
  a=SCHAR_MIN/2-1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s8*s8", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SCHAR_MIN/4-1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s8*s8", a, b));
                             EXPECT_EQUAL(c, 0);
  a=(SCHAR_MIN+4)/4, b=-4, c=0; EXPECT_TRUE(safe_iopf(&c, "s8*s8", a, b));
                            EXPECT_EQUAL(c, SCHAR_MAX-3);
  a=SCHAR_MIN/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s8*s8", b, a));
                           EXPECT_EQUAL(c, SCHAR_MIN);
  a=SCHAR_MIN/2-1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s8*s8", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SCHAR_MIN/4-1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s8*s8", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SCHAR_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s8*s8", b, a));
                          EXPECT_EQUAL(c, 0);
  a=SCHAR_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s8*s8", b, a));
                            EXPECT_EQUAL(c, -(SCHAR_MIN+1));
  return r;
}

int T_iopf_mul_s16s16() {
  int r=1;
  int16_t a, b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                     EXPECT_EQUAL(c, 100);
  a=-10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                     EXPECT_EQUAL(c, -100);
  a=10 ,b=-10, c=10; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                     EXPECT_EQUAL(c, -100);
  a=10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                    EXPECT_EQUAL(c, 0);
  a=-10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                     EXPECT_EQUAL(c, 0);
  a=0 ,b=-10, c=100; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                     EXPECT_EQUAL(c, 0);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                   EXPECT_EQUAL(c, 0);
  a=SHRT_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                           EXPECT_EQUAL(c, SHRT_MAX/2*2);
  a=SHRT_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s16*s16", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SHRT_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s16*s16", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SHRT_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s16*s16", b, a));
                           EXPECT_EQUAL(c, SHRT_MAX/2*2);
  a=SHRT_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s16*s16", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SHRT_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s16*s16", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SHRT_MIN/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                           EXPECT_EQUAL(c, SHRT_MIN);
  a=SHRT_MIN/2-1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s16*s16", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SHRT_MIN/4-1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s16*s16", a, b));
                             EXPECT_EQUAL(c, 0);
  a=(SHRT_MIN+4)/4, b=-4, c=0; EXPECT_TRUE(safe_iopf(&c, "s16*s16", a, b));
                            EXPECT_EQUAL(c, SHRT_MAX-3);
  a=SHRT_MIN/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s16*s16", b, a));
                           EXPECT_EQUAL(c, SHRT_MIN);
  a=SHRT_MIN/2-1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s16*s16", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SHRT_MIN/4-1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s16*s16", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SHRT_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s16*s16", b, a));
                          EXPECT_EQUAL(c, 0);
  a=SHRT_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s16*s16", b, a));
                            EXPECT_EQUAL(c, -(SHRT_MIN+1));
  return r;
}


int T_iopf_mul_s32s32() {
  int r=1;
  int32_t a, b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                     EXPECT_EQUAL(c, 100);
  a=-10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                     EXPECT_EQUAL(c, -100);
  a=10 ,b=-10, c=10; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                     EXPECT_EQUAL(c, -100);
  a=10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                    EXPECT_EQUAL(c, 0);
  a=-10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                     EXPECT_EQUAL(c, 0);
  a=0 ,b=-10, c=100; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                     EXPECT_EQUAL(c, 0);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                   EXPECT_EQUAL(c, 0);
  a=INT_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                           EXPECT_EQUAL(c, INT_MAX/2*2);
  a=INT_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s32*s32", a, b));
                             EXPECT_EQUAL(c, 0);
  a=INT_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s32*s32", a, b));
                             EXPECT_EQUAL(c, 0);
  a=INT_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s32*s32", b, a));
                           EXPECT_EQUAL(c, INT_MAX/2*2);
  a=INT_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s32*s32", b, a));
                             EXPECT_EQUAL(c, 0);
  a=INT_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s32*s32", b, a));
                             EXPECT_EQUAL(c, 0);
  a=INT_MIN/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                           EXPECT_EQUAL(c, INT_MIN);
  a=INT_MIN/2-1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s32*s32", a, b));
                             EXPECT_EQUAL(c, 0);
  a=INT_MIN/4-1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s32*s32", a, b));
                             EXPECT_EQUAL(c, 0);
  a=(INT_MIN+4)/4, b=-4, c=0; EXPECT_TRUE(safe_iopf(&c, "s32*s32", a, b));
                            EXPECT_EQUAL(c, INT_MAX-3);
  a=INT_MIN/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s32*s32", b, a));
                           EXPECT_EQUAL(c, INT_MIN);
  a=INT_MIN/2-1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s32*s32", b, a));
                             EXPECT_EQUAL(c, 0);
  a=INT_MIN/4-1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s32*s32", b, a));
                             EXPECT_EQUAL(c, 0);
  a=INT_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s32*s32", b, a));
                          EXPECT_EQUAL(c, 0);
  a=INT_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s32*s32", b, a));
                            EXPECT_EQUAL(c, -(INT_MIN+1));
  return r;
}


int T_iopf_mul_s64s64() {
  int r=1;
  int64_t a, b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                     EXPECT_EQUAL(c, 100);
  a=-10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                     EXPECT_EQUAL(c, -100);
  a=10 ,b=-10, c=10; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                     EXPECT_EQUAL(c, -100);
  a=10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                    EXPECT_EQUAL(c, 0);
  a=0 ,b=10, c=100; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                    EXPECT_EQUAL(c, 0);
  a=-10 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                     EXPECT_EQUAL(c, 0);
  a=0 ,b=-10, c=100; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                     EXPECT_EQUAL(c, 0);
  a=0 ,b=0, c=100; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                   EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                           EXPECT_EQUAL(c, SAFE_INT64_MAX/2*2);
  a=SAFE_INT64_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s64*s64", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s64*s64", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MAX/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s64*s64", b, a));
                           EXPECT_EQUAL(c, SAFE_INT64_MAX/2*2);
  a=SAFE_INT64_MAX/2+1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s64*s64", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MAX/4+1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s64*s64", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MIN/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                           EXPECT_EQUAL(c, SAFE_INT64_MIN);
  a=SAFE_INT64_MIN/2-1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s64*s64", a, b));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MIN/4-1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s64*s64", a, b));
                             EXPECT_EQUAL(c, 0);
  a=(SAFE_INT64_MIN+4)/4, b=-4, c=0; EXPECT_TRUE(safe_iopf(&c, "s64*s64", a, b));
                            EXPECT_EQUAL(c, SAFE_INT64_MAX-3);
  a=SAFE_INT64_MIN/2, b=2, c=0; EXPECT_TRUE(safe_iopf(&c, "s64*s64", b, a));
                           EXPECT_EQUAL(c, SAFE_INT64_MIN);
  a=SAFE_INT64_MIN/2-1, b=2, c=0; EXPECT_FALSE(safe_iopf(&c, "s64*s64", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MIN/4-1, b=4, c=0; EXPECT_FALSE(safe_iopf(&c, "s64*s64", b, a));
                             EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MIN, b=-1, c=0; EXPECT_FALSE(safe_iopf(&c, "s64*s64", b, a));
                          EXPECT_EQUAL(c, 0);
  a=SAFE_INT64_MIN+1, b=-1, c=0; EXPECT_TRUE(safe_iopf(&c, "s64*s64", b, a));
                            EXPECT_EQUAL(c, -(SAFE_INT64_MIN+1));
  return r;
}

int T_iopf_add_safe_cast_limits() {
  int r=1;
  uint8_t a, b, c;
  int8_t d;
  a=10 ,b=10, c=100, d = -20; EXPECT_FALSE(safe_iopf(&c, "u8+u8+s8", a, b, d));
                              EXPECT_EQUAL(c, 100);
  /* This shows the earlier example where subtraction is perfectly safe but
   * in order to safely cast in an operator independent way, we have declared
   * the above unsafe.
   */
  a=10 ,b=10, c=100, d = 20; EXPECT_TRUE(safe_iopf(&c, "u8+u8-s8", a, b, d));
                             EXPECT_EQUAL(c, 0);
  /* copied from T_iopf_add_s8u8u8 */
  d=-10 ,b=1, c=SCHAR_MAX+5; EXPECT_FALSE(safe_iopf(&b, "s8+u8+u8", d, b, c));
                             EXPECT_EQUAL(d, -10);
  return r;
}

int T_iopf_add_u8u8s8() {
  int r=1;
  uint8_t a, b, c;
  int8_t d;
  a=10 ,b=10, c=100, d = -20; EXPECT_FALSE(safe_iopf(&c, "u8+u8+s8", a, b, d));
                              EXPECT_EQUAL(c, 100);
  a=10 ,b=0, c=100, d = -20; EXPECT_FALSE(safe_iopf(&c, "u8+u8+s8", a, b, d));
                             EXPECT_EQUAL(c, 100);
  a=10, b=UCHAR_MAX, c=1, d = 10; EXPECT_FALSE(safe_iopf(&c, "u8+u8+s8", a, b, d));
                                  EXPECT_EQUAL(c, 1);
  a=1, b=UCHAR_MAX-2, c=1, d = 1; EXPECT_TRUE(safe_iopf(&c, "u8+u8+s8", a, b, d));
                                  EXPECT_EQUAL(c, UCHAR_MAX);
  return r;
}

int T_iopf_add_s8u8u8() {
  int r=1;
  int8_t a;
  uint8_t b, c;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&a, "s8+u8+u8", a, b, c));
                    EXPECT_EQUAL(a, 30);
  a=SCHAR_MIN ,b=1, c=SCHAR_MAX; EXPECT_TRUE(safe_iopf(&a, "s8+u8+u8", a, b, c));
                                 EXPECT_EQUAL(a, 0);
  /* Here's another operation that would succeed if casting up to the next
   * sized type was performed but is rejected by safe_iop */
  a=-10 ,b=1, c=SCHAR_MAX+5; EXPECT_FALSE(safe_iopf(&a, "s8+u8+u8", a, b, c));
                             EXPECT_EQUAL(a, -10);
  return r;
}

int T_iopf_mixed_s16u8u64() {
  int r=1;
  int16_t a = 0;
  uint8_t b = 0;
  uint64_t c = 0;
  a=10 ,b=10, c=10; EXPECT_TRUE(safe_iopf(&a, "s16+u8+u64", a, b, c));
                    EXPECT_EQUAL(a, 30);
  a=SHRT_MIN, b=UCHAR_MAX, c=SHRT_MAX-UCHAR_MAX;
    EXPECT_TRUE(safe_iopf(&a, "s16+u8+u64", a, b, c));
    EXPECT_EQUAL(a, -1);
  a=100, b=100, c=3; EXPECT_TRUE(safe_iopf(&a, "s16*u8*u64", a, b, c));
                     EXPECT_EQUAL(a, 30000);

  a=8, c=8; EXPECT_TRUE(safe_iopf(&a, "s16/u64", a, c));
            EXPECT_EQUAL(a, 1);
  a=132, b=4, c=8; EXPECT_TRUE(safe_iopf(&a, "s16-u8/u64", a, b, c));
                   EXPECT_EQUAL(a, 16);
  a=132, b=4, c=0; EXPECT_FALSE(safe_iopf(&a, "s16-u8/u64", a, b, c));
                   EXPECT_EQUAL(a, 132);
  a=1, b=4,c=2; EXPECT_TRUE(safe_iopf(&a, "s16<<u8+u64", a, b, c));
                EXPECT_EQUAL(a, 18);
  /* TODO: check this out... 
  a=5, b=1, c=1; EXPECT_TRUE(safe_iopf(&a, "s16>>u8-u64", a, b, c));
                 EXPECT_EQUAL(a, 1);
  */
  a=16, b=1, c=2; EXPECT_TRUE(safe_iopf(&a, "s16>>u8<<u64", a, b, c));
                 EXPECT_EQUAL(a, 32);
  a=16, b=1,c=100; EXPECT_FALSE(safe_iopf(&a, "s16>>u8<<u64", a, b, c));
                   EXPECT_EQUAL(a, 16);

  return r;
}




/***** MISC *****/

int T_magic_constants() {
  int r=1;
  EXPECT_EQUAL(__sio(m)(smin)(int8_t), SCHAR_MIN);
  EXPECT_EQUAL(__sio(m)(smax)(int8_t), (int8_t)(SCHAR_MAX));
  EXPECT_EQUAL(__sio(m)(umax)(uint8_t), UCHAR_MAX);

  EXPECT_EQUAL(__sio(m)(smin)(int16_t), SHRT_MIN);
  EXPECT_EQUAL(__sio(m)(smax)(int16_t), SHRT_MAX);
  EXPECT_EQUAL(__sio(m)(umax)(uint16_t), USHRT_MAX);

  EXPECT_EQUAL(__sio(m)(smin)(int32_t), INT_MIN);
  EXPECT_EQUAL(__sio(m)(smax)(int32_t), INT_MAX);
  EXPECT_EQUAL(__sio(m)(umax)(uint32_t), UINT_MAX);

  EXPECT_EQUAL(__sio(m)(smin)(int64_t), SAFE_INT64_MIN);
  EXPECT_EQUAL(__sio(m)(smax)(int64_t), SAFE_INT64_MAX);
  EXPECT_EQUAL(__sio(m)(umax)(uint64_t), SAFE_UINT64_MAX);

  EXPECT_EQUAL(__sio(m)(smin)(ssize_t), SSIZE_MIN);
  EXPECT_EQUAL(__sio(m)(smax)(ssize_t), SSIZE_MAX);
  EXPECT_EQUAL(__sio(m)(umax)(size_t), SIZE_MAX);

  EXPECT_EQUAL(__sio(m)(smin)(long), LONG_MIN);
  EXPECT_EQUAL(__sio(m)(smax)(long), LONG_MAX);
  EXPECT_EQUAL(__sio(m)(umax)(unsigned long), ULONG_MAX);

  EXPECT_EQUAL(__sio(m)(smin)(long long), LLONG_MIN);
  EXPECT_EQUAL(__sio(m)(smax)(long long), LLONG_MAX);
  EXPECT_EQUAL(__sio(m)(umax)(unsigned long long), ULLONG_MAX);

  return r;
}

#ifdef SAFE_IOP_SPEED_TEST
#include <sys/time.h>
#include <time.h>

#define SPEED_TEST(_type, _tests, _ops, _op, _fn) ({ \
  int tnum; \
  printf("%s: speed test(" #_type ", %d, %u, %s)\n", \
         __func__, _tests, _ops, #_op); \
  for (tnum=0; tnum < (_tests); ++tnum) { \
    unsigned int speed_i = 0; \
    _type speed_a=0x41, speed_b=0x42, speed_c; \
    struct timeval start, finish; \
    double raw=0, safe=0; \
    gettimeofday(&start, NULL); \
    for (speed_c=0,speed_i=0; speed_i < _ops; ++speed_i) \
      speed_c = speed_a _op speed_b; \
    for (speed_c=0,speed_i=0; speed_i < _ops; ++speed_i) \
      speed_c = speed_a _op speed_b; \
    for (speed_c=0,speed_i=0; speed_i < _ops; ++speed_i) \
      speed_c = speed_a _op speed_b; \
    gettimeofday(&finish, NULL); \
    raw = finish.tv_sec - start.tv_sec + \
          (finish.tv_usec - start.tv_usec) / 1.e6; \
    gettimeofday(&start, NULL); \
    for (speed_c=0,speed_i=0; speed_i < _ops; ++speed_i) \
      _fn(&speed_c, speed_a, speed_b); \
    for (speed_c=0,speed_i=0; speed_i < _ops; ++speed_i) \
      _fn(&speed_c, speed_a, speed_b); \
    for (speed_c=0,speed_i=0; speed_i < _ops; ++speed_i) \
      _fn(&speed_c, speed_a, speed_b); \
    gettimeofday(&finish, NULL); \
    safe = finish.tv_sec - start.tv_sec + \
          (finish.tv_usec - start.tv_usec) / 1.e6; \
    printf("%s: [%d] %u*3 ops; raw: %.9fs safe: %.9fs\n", \
           __func__, tnum, speed_i, raw, safe); \
  } \
})

int T_speed() {
  int r=1, truns=2;
  unsigned int runs = UINT_MAX;
  SPEED_TEST(size_t, truns, runs, +, safe_add);
  SPEED_TEST(unsigned long long, truns, runs, +, safe_add);
  SPEED_TEST(unsigned long, truns, runs, +, safe_add);
  SPEED_TEST(uint64_t, truns, runs, +, safe_add);
  SPEED_TEST(uint32_t, truns, runs, +, safe_add);
  SPEED_TEST(uint16_t, truns, runs, +, safe_add);
  SPEED_TEST(uint8_t, truns, runs, +, safe_add);
  SPEED_TEST(ssize_t, truns, runs, +, safe_add);
  SPEED_TEST(long long, truns, runs, +, safe_add);
  SPEED_TEST(long, truns, runs, +, safe_add);
  SPEED_TEST(int64_t, truns, runs, +, safe_add);
  SPEED_TEST(int32_t, truns, runs, +, safe_add);
  SPEED_TEST(int16_t, truns, runs, +, safe_add);
  SPEED_TEST(int8_t, truns, runs, +, safe_add);

  SPEED_TEST(size_t, truns, runs, -, safe_sub);
  SPEED_TEST(unsigned long long, truns, runs, -, safe_sub);
  SPEED_TEST(unsigned long, truns, runs, -, safe_sub);
  SPEED_TEST(uint64_t, truns, runs, -, safe_sub);
  SPEED_TEST(uint32_t, truns, runs, -, safe_sub);
  SPEED_TEST(uint16_t, truns, runs, -, safe_sub);
  SPEED_TEST(uint8_t, truns, runs, -, safe_sub);
  SPEED_TEST(ssize_t, truns, runs, -, safe_sub);
  SPEED_TEST(long long, truns, runs, -, safe_sub);
  SPEED_TEST(long, truns, runs, -, safe_sub);
  SPEED_TEST(int64_t, truns, runs, -, safe_sub);
  SPEED_TEST(int32_t, truns, runs, -, safe_sub);
  SPEED_TEST(int16_t, truns, runs, -, safe_sub);
  SPEED_TEST(int8_t, truns, runs, -, safe_sub);

  SPEED_TEST(size_t, truns, runs, *, safe_mul);
  SPEED_TEST(unsigned long long, truns, runs, *, safe_mul);
  SPEED_TEST(unsigned long, truns, runs, *, safe_mul);
  SPEED_TEST(uint64_t, truns, runs, *, safe_mul);
  SPEED_TEST(uint32_t, truns, runs, *, safe_mul);
  SPEED_TEST(uint16_t, truns, runs, *, safe_mul);
  SPEED_TEST(uint8_t, truns, runs, *, safe_mul);
  SPEED_TEST(ssize_t, truns, runs, *, safe_mul);
  SPEED_TEST(long long, truns, runs, *, safe_mul);
  SPEED_TEST(long, truns, runs, *, safe_mul);
  SPEED_TEST(int64_t, truns, runs, *, safe_mul);
  SPEED_TEST(int32_t, truns, runs, *, safe_mul);
  SPEED_TEST(int16_t, truns, runs, *, safe_mul);
  SPEED_TEST(int8_t, truns, runs, *, safe_mul);

  SPEED_TEST(size_t, truns, runs, /, safe_div);
  SPEED_TEST(unsigned long long, truns, runs, /, safe_div);
  SPEED_TEST(unsigned long, truns, runs, /, safe_div);
  SPEED_TEST(uint64_t, truns, runs, /, safe_div);
  SPEED_TEST(uint32_t, truns, runs, /, safe_div);
  SPEED_TEST(uint16_t, truns, runs, /, safe_div);
  SPEED_TEST(uint8_t, truns, runs, /, safe_div);
  SPEED_TEST(ssize_t, truns, runs, /, safe_div);
  SPEED_TEST(long long, truns, runs, /, safe_div);
  SPEED_TEST(long, truns, runs, /, safe_div);
  SPEED_TEST(int64_t, truns, runs, /, safe_div);
  SPEED_TEST(int32_t, truns, runs, /, safe_div);
  SPEED_TEST(int16_t, truns, runs, /, safe_div);
  SPEED_TEST(int8_t, truns, runs, /, safe_div);

  SPEED_TEST(size_t, truns, runs, %, safe_mod);
  SPEED_TEST(unsigned long long, truns, runs, %, safe_mod);
  SPEED_TEST(unsigned long, truns, runs, %, safe_mod);
  SPEED_TEST(uint64_t, truns, runs, %, safe_mod);
  SPEED_TEST(uint32_t, truns, runs, %, safe_mod);
  SPEED_TEST(uint16_t, truns, runs, %, safe_mod);
  SPEED_TEST(uint8_t, truns, runs, %, safe_mod);
  SPEED_TEST(ssize_t, truns, runs, %, safe_mod);
  SPEED_TEST(long long, truns, runs, %, safe_mod);
  SPEED_TEST(long, truns, runs, %, safe_mod);
  SPEED_TEST(int64_t, truns, runs, %, safe_mod);
  SPEED_TEST(int32_t, truns, runs, %, safe_mod);
  SPEED_TEST(int16_t, truns, runs, %, safe_mod);
  SPEED_TEST(int8_t, truns, runs, %, safe_mod);

  return r;
}
#endif

int main(int argc, char **argv) {
  /* test inlines */
  int tests = 0, succ = 0, fail = 0;
  tests++; if (T_shr_s8())  succ++; else fail++;
  tests++; if (T_shr_s16()) succ++; else fail++;
  tests++; if (T_shr_s32()) succ++; else fail++;
  tests++; if (T_shr_s64()) succ++; else fail++;
  tests++; if (T_shr_long()) succ++; else fail++;
  tests++; if (T_shr_longlong()) succ++; else fail++;
  tests++; if (T_shr_ssizet()) succ++; else fail++;
  tests++; if (T_shr_u8())  succ++; else fail++;
  tests++; if (T_shr_u16()) succ++; else fail++;
  tests++; if (T_shr_u32()) succ++; else fail++;
  tests++; if (T_shr_u64()) succ++; else fail++;
  tests++; if (T_shr_ulong()) succ++; else fail++;
  tests++; if (T_shr_ulonglong()) succ++; else fail++;
  tests++; if (T_shr_sizet()) succ++; else fail++;

  tests++; if (T_shl_s8())  succ++; else fail++;
  tests++; if (T_shl_s16()) succ++; else fail++;
  tests++; if (T_shl_s32()) succ++; else fail++;
  tests++; if (T_shl_s64()) succ++; else fail++;
  tests++; if (T_shl_long()) succ++; else fail++;
  tests++; if (T_shl_longlong()) succ++; else fail++;
  tests++; if (T_shl_ssizet()) succ++; else fail++;
  tests++; if (T_shl_u8())  succ++; else fail++;
  tests++; if (T_shl_u16()) succ++; else fail++;
  tests++; if (T_shl_u32()) succ++; else fail++;
  tests++; if (T_shl_u64()) succ++; else fail++;
  tests++; if (T_shl_ulong()) succ++; else fail++;
  tests++; if (T_shl_ulonglong()) succ++; else fail++;
  tests++; if (T_shl_sizet()) succ++; else fail++;

  tests++; if (T_div_s8())  succ++; else fail++;
  tests++; if (T_div_s16()) succ++; else fail++;
  tests++; if (T_div_s32()) succ++; else fail++;
  tests++; if (T_div_s64()) succ++; else fail++;
  tests++; if (T_div_long()) succ++; else fail++;
  tests++; if (T_div_longlong()) succ++; else fail++;
  tests++; if (T_div_ssizet()) succ++; else fail++;
  tests++; if (T_div_u8())  succ++; else fail++;
  tests++; if (T_div_u16()) succ++; else fail++;
  tests++; if (T_div_u32()) succ++; else fail++;
  tests++; if (T_div_u64()) succ++; else fail++;
  tests++; if (T_div_ulong()) succ++; else fail++;
  tests++; if (T_div_ulonglong()) succ++; else fail++;
  tests++; if (T_div_sizet()) succ++; else fail++;
  tests++; if (T_div_mixed()) succ++; else fail++;

  tests++; if (T_mod_s8())  succ++; else fail++;
  tests++; if (T_mod_s16()) succ++; else fail++;
  tests++; if (T_mod_s32()) succ++; else fail++;
  tests++; if (T_mod_s64()) succ++; else fail++;
  tests++; if (T_mod_long()) succ++; else fail++;
  tests++; if (T_mod_longlong()) succ++; else fail++;
  tests++; if (T_mod_ssizet()) succ++; else fail++;
  tests++; if (T_mod_u8())  succ++; else fail++;
  tests++; if (T_mod_u16()) succ++; else fail++;
  tests++; if (T_mod_u32()) succ++; else fail++;
  tests++; if (T_mod_u64()) succ++; else fail++;
  tests++; if (T_mod_ulong()) succ++; else fail++;
  tests++; if (T_mod_ulonglong()) succ++; else fail++;
  tests++; if (T_mod_sizet()) succ++; else fail++;

  tests++; if (T_mul_s8())  succ++; else fail++;
  tests++; if (T_mul_s16()) succ++; else fail++;
  tests++; if (T_mul_s32()) succ++; else fail++;
  tests++; if (T_mul_s64()) succ++; else fail++;
  tests++; if (T_mul_long()) succ++; else fail++;
  tests++; if (T_mul_longlong()) succ++; else fail++;
  tests++; if (T_mul_ssizet()) succ++; else fail++;
  tests++; if (T_mul_u8())  succ++; else fail++;
  tests++; if (T_mul_u16()) succ++; else fail++;
  tests++; if (T_mul_u32()) succ++; else fail++;
  tests++; if (T_mul_u64()) succ++; else fail++;
  tests++; if (T_mul_ulong()) succ++; else fail++;
  tests++; if (T_mul_ulonglong()) succ++; else fail++;
  tests++; if (T_mul_sizet()) succ++; else fail++;
  tests++; if (T_mul_mixed()) succ++; else fail++;

  tests++; if (T_sub_s8())  succ++; else fail++;
  tests++; if (T_sub_s16()) succ++; else fail++;
  tests++; if (T_sub_s32()) succ++; else fail++;
  tests++; if (T_sub_s64()) succ++; else fail++;
  tests++; if (T_sub_long()) succ++; else fail++;
  tests++; if (T_sub_longlong()) succ++; else fail++;
  tests++; if (T_sub_ssizet()) succ++; else fail++;
  tests++; if (T_sub_u8())  succ++; else fail++;
  tests++; if (T_sub_u16()) succ++; else fail++;
  tests++; if (T_sub_u32()) succ++; else fail++;
  tests++; if (T_sub_u64()) succ++; else fail++;
  tests++; if (T_sub_ulong()) succ++; else fail++;
  tests++; if (T_sub_ulonglong()) succ++; else fail++;
  tests++; if (T_sub_sizet()) succ++; else fail++;

  tests++; if (T_add_s8())  succ++; else fail++;
  tests++; if (T_add_s16()) succ++; else fail++;
  tests++; if (T_add_s32()) succ++; else fail++;
  tests++; if (T_add_s64()) succ++; else fail++;
  tests++; if (T_add_long()) succ++; else fail++;
  tests++; if (T_add_longlong()) succ++; else fail++;
  tests++; if (T_add_ssizet()) succ++; else fail++;
  tests++; if (T_add_u8())  succ++; else fail++;
  tests++; if (T_add_u16()) succ++; else fail++;
  tests++; if (T_add_u32()) succ++; else fail++;
  tests++; if (T_add_u64()) succ++; else fail++;
  tests++; if (T_add_ulong()) succ++; else fail++;
  tests++; if (T_add_ulonglong()) succ++; else fail++;
  tests++; if (T_add_sizet()) succ++; else fail++;
  tests++; if (T_add_mixed()) succ++; else fail++;

/* Side effects cannot be prevented without GNU C extensions */
#ifdef __GNUC__
  tests++; if (T_add_increment()) succ++; else fail++;
#endif

  tests++; if (T_iopf_null()) succ++; else fail++;
  tests++; if (T_iopf_self()) succ++; else fail++;

  tests++; if (T_iopf_add_u8u8()) succ++; else fail++;
  tests++; if (T_iopf_add_u16u16()) succ++; else fail++;
  tests++; if (T_iopf_add_u32u32()) succ++; else fail++;
  tests++; if (T_iopf_add_u64u64()) succ++; else fail++;
  tests++; if (T_iopf_add_s8s8()) succ++; else fail++;
  tests++; if (T_iopf_add_s16s16()) succ++; else fail++;
  tests++; if (T_iopf_add_s32s32()) succ++; else fail++;
  tests++; if (T_iopf_add_s64s64()) succ++; else fail++;

  tests++; if (T_iopf_mul_u8u8()) succ++; else fail++;
  tests++; if (T_iopf_mul_u16u16()) succ++; else fail++;
  tests++; if (T_iopf_mul_u32u32()) succ++; else fail++;
  tests++; if (T_iopf_mul_u32u32u32()) succ++; else fail++;
  tests++; if (T_iopf_mul_u64u64()) succ++; else fail++;

  tests++; if (T_iopf_mul_s8s8()) succ++; else fail++;
  tests++; if (T_iopf_mul_s16s16()) succ++; else fail++;
  tests++; if (T_iopf_mul_s32s32()) succ++; else fail++;
  tests++; if (T_iopf_mul_s64s64()) succ++; else fail++;


  tests++; if (T_iopf_add_safe_cast_limits()) succ++; else fail++;

  tests++; if (T_iopf_add_u8u8s8()) succ++; else fail++;
  tests++; if (T_iopf_add_s8u8u8()) succ++; else fail++;
  tests++; if (T_iopf_mixed_s16u8u64()) succ++; else fail++;
  /*
  tests++; if (T_iopf_add_u8u8s16()) succ++; else fail++;
  tests++; if (T_iopf_add_s16u8u8()) succ++; else fail++;
  tests++; if (T_iopf_add_u8u16s32()) succ++; else fail++;
  tests++; if (T_iopf_add_s16u32u8()) succ++; else fail++;
  tests++; if (T_iopf_add_s32u16u8()) succ++; else fail++;
  tests++; if (T_iopf_add_s64u32u8()) succ++; else fail++;
  */


  tests++; if (T_magic_constants()) succ++; else fail++;

  printf("%d/%d expects succeeded (%d failures)\n",
         expect_succ, expect, expect_fail);
  printf("%d/%d tests succeeded (%d failures)\n", succ, tests, fail);
  /* Currently, this requires a quiescent system to be even approximately useful.
   * TODO: use better timing functions */
#ifdef SAFE_IOP_SPEED_TEST
  T_speed();
#endif
  return fail;
}
#endif
