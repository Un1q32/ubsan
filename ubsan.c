#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#define ubsan_log(format, ...) fprintf(stderr, format, __VA_ARGS__)

const char *const ubsan_type_check_kinds[] = {"load of",
                                              "store to",
                                              "reference binding to",
                                              "member access within",
                                              "member call on",
                                              "constructor call on",
                                              "downcast of",
                                              "downcast of",
                                              "upcast of",
                                              "cast to virtual base of",
                                              "_Nonnull binding to",
                                              "dynamic operation on"};

typedef struct {
  const char *file;
  uint32_t line;
  uint32_t col;
} ubsan_source_location;

typedef struct {
  uint16_t kind;
  uint16_t info;
  char name[];
} ubsan_type_description;

typedef struct {
  ubsan_source_location loc;
  ubsan_type_description *type;
  uint8_t alignment;
  uint8_t check_kind;
} ubsan_type_mismatch_info_v1;

typedef struct {
  ubsan_source_location loc;
  ubsan_type_description *type;
} ubsan_overflow;

typedef struct {
  ubsan_source_location loc;
} ubsan_pointer_overflow;

typedef struct {
  ubsan_source_location loc;
  ubsan_type_description *array_type;
  ubsan_type_description *index_type;
} ubsan_out_of_bounds;

typedef struct {
  ubsan_source_location loc;
} ubsan_not_null_arg;

typedef struct {
  ubsan_source_location loc;
  ubsan_type_description *type;
} ubsan_invalid_value;

typedef struct {
  ubsan_source_location loc;
  ubsan_type_description *lhs_type;
  ubsan_type_description *rhs_type;
} ubsan_shift_out_of_bounds;

typedef struct {
  ubsan_source_location loc;
} ubsan_unreachable;

typedef struct {
  ubsan_source_location loc;
  ubsan_type_description *type;
} ubsan_function_type_mismatch;

typedef struct {
  ubsan_source_location loc;
  unsigned char kind;
} ubsan_invalid_builtin;

typedef struct {
  ubsan_source_location loc;
  ubsan_type_description *from;
  ubsan_type_description *to;
} ubsan_float_cast_overflow;

typedef struct {
  ubsan_source_location loc;
  ubsan_type_description *type;
} ubsan_negative_vla;

void __ubsan_handle_type_mismatch_v1(ubsan_type_mismatch_info_v1 *data,
                                     uintptr_t ptr) {
  const char *reason = "type mismatch";

  if (ptr == 0)
    reason = "dereference of a null pointer";
  else if (data->alignment && (ptr & (data->alignment - 1)))
    reason = "use of a misaligned pointer";

  ubsan_log(
      "ubsan @ %s:%u:%u: %s, %s type %s at alignment %u at address 0x%lx\n",
      data->loc.file, data->loc.line, data->loc.col, reason,
      ubsan_type_check_kinds[data->check_kind], data->type->name,
      data->alignment, ptr);
}

void __ubsan_handle_add_overflow(ubsan_overflow *data, uintptr_t lhs,
                                 uintptr_t rhs) {
  ubsan_log("ubsan @ %s:%u:%u: addition overflow, for type %s, expression %lu "
            "+ %lu\n",
            data->loc.file, data->loc.line, data->loc.col, data->type->name,
            lhs, rhs);
}

void __ubsan_handle_sub_overflow(ubsan_overflow *data, uintptr_t lhs,
                                 uintptr_t rhs) {
  ubsan_log("ubsan @ %s:%u:%u: subtraction overflow, for type %s, expression "
            "%lu - %lu\n",
            data->loc.file, data->loc.line, data->loc.col, data->type->name,
            lhs, rhs);
}

void __ubsan_handle_mul_overflow(ubsan_overflow *data, uintptr_t lhs,
                                 uintptr_t rhs) {
  ubsan_log("ubsan @ %s:%u:%u: multiplication overflow, for type %s, "
            "expression %lu * %lu\n",
            data->loc.file, data->loc.line, data->loc.col, data->type->name,
            lhs, rhs);
}

void __ubsan_handle_negate_overflow(ubsan_overflow *data, uintptr_t val) {
  ubsan_log("ubsan @ %s:%u:%u: negate overflow, for type %s, value %lu\n",
            data->loc.file, data->loc.line, data->loc.col, data->type->name,
            val);
}

void __ubsan_handle_divrem_overflow(ubsan_overflow *data, uintptr_t lhs,
                                    uintptr_t rhs) {
  ubsan_log("ubsan @ %s:%u:%u: divistion overflow, for type %s, expression %lu "
            "/ %lu\n",
            data->loc.file, data->loc.line, data->loc.col, data->type->name,
            lhs, rhs);
}

void __ubsan_handle_pointer_overflow(ubsan_pointer_overflow *data,
                                     uintptr_t base, uintptr_t result) {
  ubsan_log("ubsan @ %s:%u:%u: pointer overflow, base 0x%lx, result 0x%lx\n",
            data->loc.file, data->loc.line, data->loc.col, base, result);
}

void __ubsan_handle_out_of_bounds(ubsan_out_of_bounds *data, uintptr_t index) {
  ubsan_log("ubsan @ %s:%u:%u: array out of bounds, for type %s, by index type "
            "%s %lu\n",
            data->loc.file, data->loc.line, data->loc.col,
            data->array_type->name, data->index_type->name, index);
}

void __ubsan_handle_nonnull_arg(ubsan_not_null_arg *data) {
  ubsan_log("ubsan @ %s:%u:%u: not-null argument is null\n", data->loc.file,
            data->loc.line, data->loc.col);
}

void __ubsan_handle_load_invalid_value(ubsan_invalid_value *data,
                                       uintptr_t val) {
  ubsan_log("ubsan @ %s:%u:%u: load of invalid value, for type %s, value %lu\n",
            data->loc.file, data->loc.line, data->loc.col, data->type->name,
            val);
}

void __ubsan_handle_shift_out_of_bounds(ubsan_shift_out_of_bounds *data,
                                        uintptr_t lhs, uintptr_t rhs) {
  ubsan_log("ubsan @ %s:%u:%u: shift out of bounds, of type %s and %s, value "
            "%lu and %lu\n",
            data->loc.file, data->loc.line, data->loc.col, data->lhs_type->name,
            data->rhs_type->name, lhs, rhs);
}

void __ubsan_handle_builtin_unreachable(ubsan_unreachable *data) {
  ubsan_log("ubsan @ %s:%u:%u: unreachable code was reached\n", data->loc.file,
            data->loc.line, data->loc.col);
}

void __ubsan_handle_function_type_mismatch(ubsan_function_type_mismatch *data,
                                           void *function) {
  ubsan_log("ubsan @ %s:%u:%u: function type mismatch, for type %s at address "
            "0x%lx\n",
            data->loc.file, data->loc.line, data->loc.col, data->type->name,
            function);
}

void __ubsan_handle_invalid_builtin(ubsan_invalid_builtin *data) {
  if (data->kind == 2)
    ubsan_log("ubsan @ %s:%u:%u: assumption is violated during execution\n",
              data->loc.file, data->loc.line, data->loc.col);
  else
    ubsan_log("ubsan @ %s:%u:%u: passing zero to __builtin_%s(), which is not "
              "a valid argument\n",
              data->loc.file, data->loc.line, data->loc.col,
              (data->kind == 0) ? "ctz" : "clz");
}

void __ubsan_handle_float_cast_overflow(ubsan_float_cast_overflow *data,
                                        uintptr_t _value) {
  long double value;
  if (data->from->info == 16) {
    union {
      uint16_t i;
      _Float16 f;
    } un;
    un.i = _value;
    value = un.f;
  } else if (data->from->info == 32) {
    union {
      uint32_t i;
      float f;
    } un;
    un.i = _value;
    value = un.f;
  } else if (data->from->info == 64)
    value = *(double *)_value;
  /*
  else if (data->from->info == 128)
    value = *(_Float128 *)_value;
  */
  else if (data->from->info > 64)
    value = *(long double *)_value;
  else {
    ubsan_log("ubsan @ %s:%u:%u: overflow when casting %s to %s\n",
              data->loc.file, data->loc.line, data->loc.col, data->from->name,
              data->to->name);
    return;
  }
  ubsan_log(
      "ubsan @ %s:%u:%u: %Lg is outside the range of representable values "
      "of type %s\n",
      data->loc.file, data->loc.line, data->loc.col, value, data->to->name);
}

void __ubsan_handle_vla_bound_not_positive(ubsan_negative_vla *data) {
  ubsan_log("ubsan @ %s:%u:%u: variable length array bound evaluates to "
            "negative value\n",
            data->loc.file, data->loc.line, data->loc.col);
}
