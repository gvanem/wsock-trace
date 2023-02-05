/**\file    csv.h
 * \ingroup Misc
 */
#ifndef _CSV_H
#define _CSV_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \enum The CSV-parser states
 */
typedef enum CSV_STATE {
        STATE_ILLEGAL = 0,
        STATE_NORMAL,
        STATE_QUOTED,
        STATE_ESCAPED,
        STATE_COMMENT,
        STATE_STOP,
        STATE_EOF
      } CSV_STATE;

struct CSV_context;

/**
 * \typedef The CSV-parser state-functions matches this:
 */
typedef void (*csv_state_t) (struct CSV_context *ctx);

/**
 * \typedef CSV_cfile
 * Data needed to generate a .c-file
 */
typedef struct CSV_cfile {
        const char *file_name;
        FILE       *file;
      } CSV_cfile;

/**
 * \typedef CSV_context
 * Keep all data used for CSV parsing in this context.
 */
typedef struct CSV_context {
        const char *file_name;
        FILE       *file;
        unsigned    field_num;
        unsigned    num_fields;
        size_t     *field_sizes;
        int         delimiter;
        int       (*callback) (struct CSV_context *ctx, const char *value);
        unsigned    rec_num;
        unsigned    rec_max;
        unsigned    line_num;
        unsigned    line_size;
        unsigned    comment_lines;
        unsigned    empty_lines;
        unsigned    parse_errors;
        char       *parse_buf, *parse_ptr;
        csv_state_t state_func;
        CSV_STATE   state;
        int         c_in;
        int         BOM_found;
        CSV_cfile   cfile;
      } CSV_context;

extern int CSV_test_errors;
extern int CSV_test_generate;
extern int CSV_test_verbose;
extern int CSV_test_dump;

#define CSV_TRACE(level, fmt, ...) do {                             \
                                     if (CSV_test_verbose >= level) \
                                        printf ("%s(%u): " fmt,     \
                                                __FILE__, __LINE__, \
                                                ## __VA_ARGS__);    \
                                   } while (0)

#define CSV_ASSERT(expr) do {                                       \
                           if (!(expr)) {                           \
                              fprintf (stderr, "FAIL: %s:%d: %s\n", \
                                       __FILE__, __LINE__, #expr);  \
                              CSV_test_errors++;                    \
                           }                                        \
                         } while (0)

unsigned    CSV_open_and_parse_file (struct CSV_context *ctx);
FILE       *CSV_fopen_excl (const char *file, const char *mode);

size_t      CSV_generic_read_bin  (const char *fname,       void **data, size_t *data_size_p);
size_t      CSV_generic_write_bin (const char *fname, const void *data, size_t data_size,
                                   size_t rec_size, int overwrite);

size_t      CSV_generic_write_data  (void *data, size_t data_size,
                                     size_t rec_size, unsigned rec_idx,
                                     const char *field_value,
                                     size_t field_size, size_t field_ofs);

size_t      CSV_generic_alloc     (void **data, size_t *data_size_p, size_t sz);
size_t      CSV_generic_free      (void **data, size_t *sz);

typedef int (*CSV_bsearch_func) (const void *key, const void *member);

const void *CSV_generic_lookup (const char *key, unsigned field, size_t field_size, size_t field_ofs,
                                const void *data, size_t data_size, size_t rec_size, size_t max_records,
                                CSV_bsearch_func cmp_func);

void        CSV_generic_dump (const void *record_data, unsigned rec_num,
                              unsigned field, size_t field_ofs);

#ifdef __cplusplus
}
#endif

#endif /* _CSV_H */
