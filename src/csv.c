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

#define DEFAULT_BUF_SIZE 1000

#define PUTC(c)  do {                                                    \
                   if (ctx->parse_ptr < ctx->parse_buf + ctx->line_size) \
                      *ctx->parse_ptr++ = c;                             \
                 } while (0)

/**
 * A simple state-machine for parsing CSV records.
 *
 * The parser starts in this state.
 */
static void state_normal (struct CSV_context *ctx)
{
  if (ctx->c_in == ctx->delimiter)
  {
    ctx->state = STATE_STOP;
    return;
  }
  switch (ctx->c_in)
  {
    case -1:
         TRACE (3, "%s() reached EOF at rec: %u, line: %u, field: %u.\n",
                __FUNCTION__, ctx->rec_num, ctx->line_num, ctx->field_num);
         ctx->state = STATE_EOF;
         break;
    case '"':
         ctx->state = STATE_QUOTED;
         break;
    case '\r':     /* ignore */
         break;
    case '\n':
         ctx->line_num++;
         if (ctx->field_num > 0)     /* If field == 0, ignore empty lines */
              ctx->state = STATE_STOP;
         else ctx->empty_lines++;
         break;
    case '#':
         if (ctx->field_num == 0)    /* If field == 0, ignore comment lines */
         {
           ctx->state = STATE_COMMENT;
           ctx->comment_lines++;
         }
         else
           PUTC (ctx->c_in);
         break;
    default:
         PUTC (ctx->c_in);
         break;
  }
}

/**
 * If the parser find a quote (`"`) in `state_normal()`, it enters this state
 * to find the end of the quote. Ignoring escaped quotes (i.e. a `\\"`).
 */
static void state_quoted (struct CSV_context *ctx)
{
  switch (ctx->c_in)
  {
    case -1:
         TRACE (3, "%s() reached EOF at rec: %u, line: %u, field: %u.\n",
                __FUNCTION__, ctx->rec_num, ctx->line_num, ctx->field_num);
         ctx->state = STATE_EOF;
         break;
    case '"':
         ctx->state = STATE_NORMAL;
         break;
    case '\r':     /* ignore, but should not occur since `fopen (file, "rt")` was used */
         break;
    case '\n':     /* add a space in this field */
         PUTC (' ');
         ctx->line_num++;
         break;
    case '\\':
         ctx->state = STATE_ESCAPED;
         break;
    default:
         PUTC (ctx->c_in);
         break;
  }
}

/**
 * Look for an escaped quote. <br>
 * Go back to `state_quoted()` when found.
 */
static void state_escaped (struct CSV_context *ctx)
{
  switch (ctx->c_in)
  {
    case -1:
         TRACE (3, "%s() reached EOF at rec: %u, line: %u, field: %u.\n",
                __FUNCTION__, ctx->rec_num, ctx->line_num, ctx->field_num);
         ctx->state = STATE_EOF;
         break;
    case '"':       /* '\"' -> '"' */
         PUTC ('"');
         ctx->state = STATE_QUOTED;
         break;
    case '\r':
         break;
    case '\n':
         ctx->line_num++;
         break;
    default:
         ctx->state = STATE_QUOTED; /* Unsupported ctrl-char. Go back */
         break;
  }
}

/**
 * Do nothing until a newline. <br>
 * Go back to `state_normal()` when found.
 */
static void state_comment (struct CSV_context *ctx)
{
  switch (ctx->c_in)
  {
    case -1:
         TRACE (3, "%s() reached EOF at rec: %u, line: %u, field: %u.\n",
                __FUNCTION__, ctx->rec_num, ctx->line_num, ctx->field_num);
         ctx->state = STATE_EOF;
         break;
    case '\n':
         ctx->line_num++;
         ctx->state = STATE_NORMAL;
         break;
  }
}

static void state_illegal (struct CSV_context *ctx)
{
  TRACE (2, "%s(): I did not expect this!\n", __FUNCTION__);
  ctx->state = STATE_EOF;
}

static const char *state_name (CSV_STATE state)
{
  return (state == STATE_ILLEGAL ? "STATE_ILLEGAL" :
          state == STATE_NORMAL  ? "STATE_NORMAL " :
          state == STATE_QUOTED  ? "STATE_QUOTED " :
          state == STATE_ESCAPED ? "STATE_ESCAPED" :
          state == STATE_COMMENT ? "STATE_COMMENT" :
          state == STATE_STOP    ? "STATE_STOP   " :
          state == STATE_EOF     ? "STATE_EOF    " : "??");
}

/**
 * Read from `ctx->file` until end-of-field.
 */
static const char *CSV_get_next_field (struct CSV_context *ctx)
{
  char      *ret;
  CSV_STATE  new_state = STATE_ILLEGAL;
  CSV_STATE  old_state = STATE_ILLEGAL;
  unsigned   line;

  ctx->parse_ptr = ctx->parse_buf;

  while (1)
  {
    ctx->c_in = fgetc (ctx->file);

    old_state = ctx->state;  (*ctx->state_func) (ctx);
    new_state = ctx->state;

    /* Set new state for this context. (Or stay in ame state).
     */
    switch (new_state)
    {
      case STATE_NORMAL:
           ctx->state_func = state_normal;
           break;
      case STATE_QUOTED:
           ctx->state_func = state_quoted;
           break;
      case STATE_ESCAPED:
           ctx->state_func = state_escaped;
           break;
      case STATE_COMMENT:
           ctx->state_func = state_comment;
           break;
      case STATE_ILLEGAL:   /* Avoid compiler warning */
      case STATE_STOP:
      case STATE_EOF:
           break;
    }
    if (new_state != old_state)
       TRACE (3, "%s -> %s\n", state_name(old_state), state_name(new_state));

    if (new_state == STATE_STOP && ctx->delimiter == ' ')
    {
      while ((ctx->c_in = fgetc (ctx->file)) == ' ') ;
      ungetc (ctx->c_in, ctx->file);
    }

    if (new_state == STATE_STOP || new_state == STATE_EOF)
       break;
  }

  *ctx->parse_ptr = '\0';
  ret = str_ltrim (ctx->parse_buf);

  line = ctx->line_num;
  if (ctx->c_in == '\n')
     line--;

  TRACE (3, "rec: %u, line: %u, field: %u: '%s'.\n", ctx->rec_num, line, ctx->field_num, ret);

  if (new_state == STATE_EOF)
     return (NULL);
  return (ret);
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
    const char *val;
    unsigned    line;
    int         rc;

    ctx->state = STATE_NORMAL;
    ctx->state_func = state_normal;

    val  = CSV_get_next_field (ctx);
    line = ctx->line_num;
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
    TRACE (2, "  Ignoring parse-error on line %u, field %u.\n", ctx->line_num, ctx->field_num);
    return (1);
  }
  if (ctx->state == STATE_EOF)
  {
    TRACE (3, "  Reached EOF on line %u, field %u.\n", ctx->line_num, ctx->field_num);
    return (0);
  }
  TRACE (2, "  Unable to parse line %u, field %u.\n", ctx->line_num, ctx->field_num);
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
    TRACE (0, "'ctx->num_fields' must be > 0.\n");
    return (0);
  }

  if (!ctx->delimiter)
     ctx->delimiter = ',';

  if (strchr("#\"\r\n", ctx->delimiter))
  {
    TRACE (0, "Illegal field delimiter '%c'.\n", ctx->delimiter);
    return (0);
  }
  TRACE (3, "Using field-delimiter: '%c'.\n", ctx->delimiter);

  if (ctx->rec_max == 0)
     ctx->rec_max = UINT_MAX;

  if (!ctx->callback)
  {
    TRACE (0, "'ctx->callback' must be set.\n");
    return (0);
  }
  if (!ctx->file_name)
  {
    TRACE (0, "'ctx->file_name' must be set.\n");
    return (0);
  }

  if (ctx->line_size == 0)
     ctx->line_size = DEFAULT_BUF_SIZE;

  ctx->parse_buf = malloc (ctx->line_size+1);
  if (!ctx->parse_buf)
  {
    TRACE (1, "Allocation of 'parse_buf' failed.\n");
    return (0);
  }
  ctx->file = fopen (ctx->file_name, "rt");
  if (!ctx->file)
  {
    TRACE (1, "Failed to open file \"%s\". errno: %d\n", ctx->file_name, errno);
    free (ctx->parse_buf);
    return (0);
  }

  if (setvbuf (ctx->file, NULL, _IOFBF, 2*ctx->line_size))
     TRACE (1, "Failed to call 'setvbuf()' on \"%s\", errno: %d\n", ctx->file_name, errno);

  ctx->state_func = state_illegal;
  ctx->state      = STATE_ILLEGAL;
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

  while (1)
  {
    if (!CSV_parse_file(ctx) || ctx->rec_num >= ctx->rec_max)
       break;
  }
  fclose (ctx->file);
  ctx->file = NULL;
  free (ctx->parse_buf);
  return (ctx->rec_num);
}

/*
 * A simple test program for the above CVS-parser.
 */
#ifdef TEST_CSV

#include "getopt.h"

/* For getopt.c.
 */
const char *program_name = "csv.exe";

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
  while (s[0] && s[1] && isspace ((int)s[0]))
       s++;
  return (s);
}

/*
 * A do-nothing callback. Just report the parsed record and fields.
 */
static int csv_callback (struct CSV_context *ctx, const char *value)
{
  static int rec_num = 0;

  if (ctx->rec_num > rec_num)
     puts ("");
  TRACE (0, "rec: %u, line: %u, field: %u, value: '%s'.\n", ctx->rec_num, ctx->line_num, ctx->field_num, value);
  rec_num = ctx->rec_num;
  return (1);
}

static int usage (void)
{
  puts ("Usage: csv.exe [-d] [-f field-delimiter] [-m records] <-n number-of-fields> <file.csv>\n"
        "       -d: increase trace-level            (optional).\n"
        "       -f: set field delimiter             (optional, default is ',').\n"
        "       -m: max number of records to handle (optional).\n"
        "       -n: number of fields in CSV-records (mandatory).");
  exit (0);
}

int main (int argc, char **argv)
{
  struct CSV_context ctx;
  int    ch;

  memset (&ctx, '\0', sizeof(ctx));

  while ((ch = getopt(argc, argv, "df:m:n:h?")) != EOF)
     switch (ch)
     {
       case 'f':
            ctx.delimiter = optarg[0];
            break;
       case 'm':
            ctx.rec_max = atoi (optarg);
            break;
       case 'n':
            ctx.num_fields = atoi (optarg);
            break;
       case 'd':
            g_cfg.trace_level++;
            break;
       case '?':
       case 'h':
       default:
            usage();
            break;
  }
  argv += optind;
  if (!*argv)
     usage();

  ctx.file_name = argv[0];
  ctx.callback  = csv_callback;
  return CSV_open_and_parse_file (&ctx) > 0 ? 0 : 1;
}
#endif  /* TEST_CSV */
