/**\file    csv.h
 * \ingroup Misc
 */
#ifndef _CSV_H
#define _CSV_H

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
        STATE_EOF,
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
        size_t     *field_sizes;
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

unsigned CSV_open_and_parse_file (struct CSV_context *ctx);

size_t   CSV_generic_read_bin  (const char *fname,       void **data, size_t *data_size_p);
size_t   CSV_generic_write_bin (const char *fname, const void *data, size_t data_size, size_t rec_size, int overwrite);

void     CSV_generic_alloc     (void **data, size_t *data_size_p, size_t sz);
void     CSV_generic_free      (void **data, size_t *sz);

void    *CSV_generic_lookup    (const char *key, size_t key_size, int key_ofs, void *data,
                                size_t data_size, size_t rec_size, size_t max_records,
                                int use_bsearch);

unsigned CSV_generic_gen_data  (void *data, size_t data_size,
                                size_t rec_size, unsigned rec_idx,
                                const char *key, int key_ofs, int key_size);

#endif /* _CSV_H */
