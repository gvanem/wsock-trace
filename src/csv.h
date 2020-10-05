/**\file    csv.h
 * \ingroup Misc
 */
#ifndef _CSV_H
#define _CSV_H

/**
 * \enum The CSV-parser states
 */
typedef enum CSV_STATE {
        STATE_NO_CHANGE = 0,
        STATE_NORMAL,
        STATE_QUOTED,
        STATE_ESCAPED,
        STATE_STOP
      } CSV_STATE;

struct CSV_context;

/**
 * \typedef The CSV-parser state-functions matches this:
 */
typedef CSV_STATE (*csv_state_t) (struct CSV_context *ctx);

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
        unsigned    parse_errors;
        char       *parse_buf;
        csv_state_t state_func;
        CSV_STATE   state_change;
        int         c_in, c_out;
      } CSV_context;

unsigned CSV_open_and_parse_file (struct CSV_context *ctx);

#endif /* _CSV_H */
