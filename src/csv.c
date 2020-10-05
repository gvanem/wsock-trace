/**\file    csv.c
 * \ingroup Misc
 *
 * \brief Implements a generic parser for CSV files.
 *
 * The parsing is loosely adapting the rules in: https://tools.ietf.org/html/rfc4180
 */
#include <limits.h>
#include <errno.h>

#include "common.h"
#include "init.h"
#include "csv.h"

/**
 * A simple state-machine for parsing CSV records.
 *
 * The parser starts in this state.
 */
static CSV_STATE state_normal (struct CSV_context *ctx)
{
  if (ctx->c_in == ctx->delimiter)
     return (STATE_STOP);

  switch (ctx->c_in)
  {
    case -1:       /* EOF */
         return (STATE_STOP);
    case '"':
         return (STATE_QUOTED);
    case '\r':     /* ignore */
         break;
    case '\n':
         ctx->line_num++;
         return (STATE_STOP);
    default:
         ctx->c_out = ctx->c_in;
         break;
  }
  return (STATE_NO_CHANGE);
}

/**
 * If the parser find a quote (`"`) in `state_normal()`, it enters this state
 * to find the end of the quote. Ignoring escaped quotes (i.e. a `\\"`).
 */
static CSV_STATE state_quoted (struct CSV_context *ctx)
{
  switch (ctx->c_in)
  {
    case -1:        /* EOF */
         return (STATE_STOP);
    case '"':
         return (STATE_NORMAL);
    case '\r':     /* ignore, but should not occur since `fopen (file, "rt")` was used */
         break;
    case '\n':     /* add a space in this field */
         ctx->c_out = ' ';
         ctx->line_num++;
         break;
    case '\\':
         return (STATE_ESCAPED);
    default:
         ctx->c_out = ctx->c_in;
         break;
  }
  return (STATE_NO_CHANGE);
}

/**
 * Look for an escaped quote. <br>
 * Go back to `state_quoted()` when found.
 */
static CSV_STATE state_escaped (struct CSV_context *ctx)
{
  switch (ctx->c_in)
  {
    case -1:        /* EOF */
         return (STATE_STOP);
    case '"':       /* '\"' -> '"' */
         ctx->c_out = '"';
         return (STATE_QUOTED);
    case '\r':
         break;
    case '\n':
         ctx->line_num++;
         break;
    default:
         return (STATE_QUOTED); /* Unsupported ctrl-char. Go back */
  }
  return (STATE_NO_CHANGE);
}

/**
 * Read from `ctx->file` until end-of-field.
 */
static const char *CSV_get_next_field (struct CSV_context *ctx)
{
  char      *out = ctx->parse_buf;
  CSV_STATE  state;
  unsigned   line;

  ctx->c_in = 0;
  while (1)
  {
    ctx->c_in  = fgetc (ctx->file);
    ctx->c_out = 0;
    state = (*ctx->state_func) (ctx);

    if (ctx->c_out && out < out + sizeof(ctx->parse_buf) - 1)
       *out++ = ctx->c_out;

    if (state == STATE_STOP)
       break;
    if (state == STATE_NORMAL)
       ctx->state_func = state_normal;
    else if (state == STATE_QUOTED)
       ctx->state_func = state_quoted;
    else if (state == STATE_ESCAPED)
       ctx->state_func = state_escaped;
  }
  ctx->state_change = state;   /* New state of of this context */
  *out = '\0';                 /* 0-terminate this field in this context */

  /* Check for empty lines or lines with leading space or comments in file.
   * Do it by recursing.
   */
  out = str_ltrim (ctx->parse_buf);
#if 1
  if (*out == '#' || *out == ';' || (ctx->c_in != ctx->delimiter && *out == '\0'))
  {
    ctx->line_num++;
    return CSV_get_next_field (ctx);
  }
#endif

  line = ctx->line_num;
  if (ctx->c_in == '\n')
     line--;
  TRACE (3, "rec: %u, line: %2u, field: %d: '%s'.\n", ctx->rec_num, line, ctx->field_num, out);
  return (out);
}

/**
 * Open and parse CSV file and extract one record by calling the callback for each found field.
 *
 * \param[in]  ctx  the CSV context to work with.
 * \retval     the number of CSV-records that could be parsed.
 */
static int CSV_parse_file (struct CSV_context *ctx)
{
  for (ctx->field_num = 0; ctx->field_num < ctx->num_fields; ctx->field_num++)
  {
    const char *val = CSV_get_next_field (ctx);
    unsigned    line = ctx->line_num;
    int   rc;

    if (!val)
       goto quit;

     if (ctx->c_in == '\n')   /* Fix the line-number if the last char read was a newline */
        ctx->line_num--;

     rc = (*ctx->callback) (ctx, val);
     ctx->line_num = line;    /* Restore line-number */

     if (!rc)
        break;
  }

  ctx->rec_num++;
  TRACE (3, "\n");
  return (ctx->field_num == ctx->num_fields);

quit:
  if (ctx->line_num == 1)
  {
    TRACE (2, "  Ignoring parse-error on line %d, field %d.\n", ctx->line_num, ctx->field_num);
    return (1);
  }
  TRACE (2, "  Unable to parse line %u, field %d.\n", ctx->line_num, ctx->field_num);
  ctx->parse_errors++;
  return (0);
}

/**
 * Check for unset members of the CSV-context. <br>
 * Set the field-delimiter to `,` if not already done.
 *
 * \param[in]  ctx  the CSV context to work with.
 * \retval     1 if the members are okay.
 */
static int CSV_check_and_fill_ctx (struct CSV_context *ctx)
{
  if (ctx->num_fields == 0)
  {
    TRACE (1, "'ctx->num_fields' must be > 0.\n");
    return (0);
  }
  if (!ctx->callback)
  {
    TRACE (1, "'ctx->callback' must be set.\n");
    return (0);
  }
  ctx->file = fopen (ctx->file_name, "rt");
  if (!ctx->file)
  {
    TRACE (1, "Failed to open file \"%s\". errno: %d\n", ctx->file_name, errno);
    return (0);
  }

  if (!ctx->delimiter)
     ctx->delimiter = ',';

  TRACE (2, "Using field-delimiter: '%c'.\n", ctx->delimiter);

  ctx->state_func = state_normal;
  ctx->rec_num    = 0;
  ctx->line_num   = 1;
  return (1);
}

/**
 * Open and parse a CSV-file.
 */
unsigned CSV_open_and_parse_file (struct CSV_context *ctx)
{
  if (!CSV_check_and_fill_ctx(ctx))
     return (0);

  while (!feof(ctx->file))
  {
    CSV_parse_file (ctx);
    if (ctx->rec_num > ctx->rec_max)
       break;
  }
  fclose (ctx->file);
  ctx->file = NULL;
  return (ctx->rec_num);
}

/*
 * A simple test program for the above CVS-parser.
 */
#ifdef TEST_CSV
struct config_table g_cfg;

/*
 * Copy some functions from common.c to keep the Makefiles tidy.
 */
void debug_printf (const char *file, unsigned line, const char *fmt, ...)
{
  va_list args;

  printf ("%s(%u): ", file, line);
  va_start (args, fmt);
  vprintf (fmt, args);
  va_end (args);
}

/*
 * Trim leading blanks (space/tab) from a string.
 */
char *str_ltrim (char *s)
{
  assert (s != NULL);

  while (s[0] && s[1] && isspace ((int)s[0]))
       s++;
  return (s);
}

/*
 * A do-nothing callback. Just report the parsed records.
 */
static int csv_callback (struct CSV_context *ctx, const char *value)
{
  TRACE (2, "rec: %u, line %u, field %u, value: '%s'.\n", ctx->rec_num, ctx->line_num, ctx->field_num, value);
  return (1);
}

static int usage (void)
{
  puts ("Usage: csv.exe [-d] [-f field-delimiter] <file.csv>");
  return (1);
}

int main (int argc, char **argv)
{
  struct CSV_context ctx;

  if (argc < 2)
     return usage();

  if (!strcmp(argv[1], "-d"))
  {
    argc--;
    argv++;
    g_cfg.trace_level = 2;
  }

  memset (&ctx, '\0', sizeof(ctx));
  if (!strcmp(argv[1], "-f"))
  {
    ctx.delimiter = argv[2][0];
    argc -= 2;
    argv += 2;
  }

  ctx.file_name  = argv[1];
  ctx.rec_max    = 4;
  ctx.num_fields = 7;
  ctx.callback   = csv_callback;
  return CSV_open_and_parse_file (&ctx) > 0 ? 0 : 1;
}
#endif  /* TEST_CSV */
