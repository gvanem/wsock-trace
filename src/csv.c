/**\file    csv.c
 * \ingroup Misc
 *
 * \brief Implements a generic parser for CSV files.
 *
 * The parsing is loosely adapting the rules in: https://tools.ietf.org/html/rfc4180
 */
#include <limits.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "common.h"
#include "init.h"
#include "getopt.h"
#include "csv.h"

#if !defined(CSV_TEST)  /* Not needed in a generated .c-file */

#define DEFAULT_BUF_SIZE 1000

#define PUTC(c)  do {                                                    \
                   if (ctx->parse_ptr < ctx->parse_buf + ctx->line_size) \
                      *ctx->parse_ptr++ = c;                             \
                 } while (0)

static NO_INLINE int  CSV_cfile_open (struct CSV_context *ctx);
static NO_INLINE void CSV_cfile_close (struct CSV_context *ctx);

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
    case '\r':     /* ignore */
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
    case '\r':
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

    /* Set new state for this context. (Or stay in same state).
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

    if (new_state == STATE_STOP && (isspace(ctx->delimiter) || iscntrl(ctx->delimiter)))
    {
      while (1)
      {
        ctx->c_in = fgetc (ctx->file);
        if (ctx->c_in != ' ' && ctx->c_in != ctx->delimiter)
           break;
      }
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
 * Try to auto-detect the number of fields in the CSV-file.
 *
 * Open and parse the first non-comment line and count the number of delimiters.
 * If this line ends in a newline, this should count as the last field.
 * Hence increment by 1.
 *
 * \param[in]  ctx  the CSV context to work with.
 * \retval     0 on failure. 1 on success.
 */
static int CSV_autodetect_num_fields (struct CSV_context *ctx)
{
  unsigned    num_fields = 0;
  unsigned    line = 0;
  uint32_t    BOM = 0;
  const char *delim, *next;

  ctx->file = fopen (ctx->file_name, "rb");
  if (!ctx->file)
     return (0);

  while (1)
  {
    if (!fgets(ctx->parse_buf, ctx->line_size, ctx->file))
       return (0);

    line++;

    /* Handle an UTF-8 BOM at line 1
     */
    if (line == 1)
    {
      BOM = (BYTE)ctx->parse_buf[2] + ((BYTE)ctx->parse_buf[1] << 8) + ((BYTE)ctx->parse_buf[0] << 16);
      TRACE (2, "BOM: 0x%06X.\n", BOM);
      if (BOM == 0xEFBBEF || BOM == 0xEFBBBF)
         ctx->BOM_found = 1;
    }

    /* Ignore comment lines
     */
    if (!strchr(ctx->parse_buf, '#'))
       break;
  }

  delim = ctx->parse_buf;
  while (*delim)
  {
    next = strchr (delim, ctx->delimiter);
    if (!next)
    {
      if (strchr(delim, '\r') || strchr(delim, '\n'))
         num_fields++;
      break;
    }
    delim = next + 1;
    num_fields++;
  }

  ctx->num_fields = num_fields;
  fclose (ctx->file);
  ctx->file = NULL;
  TRACE (2, "Auto-detected num_field %u. BOM found: %d\n", num_fields, ctx->BOM_found);
  return (1);
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
  int delim;

  ctx->BOM_found = 0;
  if (!ctx->delimiter)
     ctx->delimiter = ',';
  delim = ctx->delimiter;

  if (isalnum(delim) || strchr("#.\"\r\n", delim))
  {
    TRACE (0, "Illegal field delimiter '%c' (%d).\n", delim, delim);
    return (0);
  }
  TRACE (2, "Using field-delimiter: '%c'.\n", ctx->delimiter);

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

  TRACE (2, "Opening file \"%s\".\n", ctx->file_name);

  if (ctx->num_fields == 0 && !CSV_autodetect_num_fields(ctx))
  {
    free (ctx->parse_buf);
    return (0);
  }

  ctx->file = fopen (ctx->file_name, "rt");
  if (!ctx->file)
  {
    TRACE (1, "Failed to open file \"%s\". errno: %d\n", ctx->file_name, errno);
    free (ctx->parse_buf);
    return (0);
  }

  if (setvbuf(ctx->file, NULL, _IOFBF, 2*ctx->line_size))
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
  if (!CSV_check_and_fill_ctx(ctx) || !CSV_cfile_open(ctx))
     return (0);

  while (1)
  {
    if (!CSV_parse_file(ctx) || ctx->rec_num >= ctx->rec_max)
       break;
  }
  fclose (ctx->file);
  ctx->file = NULL;
  free (ctx->parse_buf);
  CSV_cfile_close (ctx);

  return (ctx->rec_num);
}

/*
 * A simple test program for the above CVS-parser.
 *
 * A do-nothing callback. Just report the parsed record and fields.
 */
static int csv_callback (struct CSV_context *ctx, const char *value)
{
  static unsigned rec_num = 0;
  size_t sz;

  if (ctx->cfile.field_sizes)
  {
    sz = strlen (value);
    if (ctx->cfile.field_sizes [ctx->field_num] < sz)
        ctx->cfile.field_sizes [ctx->field_num] = sz + 1;
  }
  else
  {
    if (ctx->rec_num > rec_num)
       puts ("");
    TRACE (0, "rec: %u, field: %u, value: '%s'.\n", ctx->rec_num, ctx->field_num, value);
  }

  rec_num = ctx->rec_num;
  return (1);
}

static int show_help (void)
{
  printf ("Usage:\n"
          "  %s [-f field-delimiter] [-m records] <-n number-of-fields> <-g c-file> <file.csv>\n"
          "    -f: set field delimiter. Use '\\t' for a <TAB> or '\\s for a <SPACE> delimiter (default is ',').\n"
          "    -m: max number of records to handle.\n"
          "    -n: number of fields in CSV-records. Default is found by auto-detection.\n"
          "    -g: generate a .c-file to represent the data (use '-' for stdout).\n",
          g_data.program_name);
  return (0);
}

int csv_main (int argc, char **argv)
{
  struct CSV_context ctx;
  int    ch, rc;

  set_program_name (argv[0]);
  memset (&ctx, '\0', sizeof(ctx));

  while ((ch = getopt(argc, argv, "f:m:n:g:h?")) != EOF)
     switch (ch)
     {
       case 'f':
            if (!strcmp(optarg, "'") || !strcmp(optarg, "\\s"))
            {
              ctx.delimiter = ' ';
              TRACE (1, "Using <space> as field-delimiter.\n");
            }
            else if (!strcmp(optarg, "\\t"))
            {
              ctx.delimiter = '\t';
              TRACE (1, "Using <TAB> as field-delimiter.\n");
            }
            else
              ctx.delimiter = optarg[0];
            break;
       case 'm':
            ctx.rec_max = atoi (optarg);
            break;
       case 'n':
            ctx.num_fields = atoi (optarg);
            break;
       case 'g':
            ctx.cfile.file_name = optarg;
            break;
       case '?':
       case 'h':
       default:
            return show_help();
  }

  argv += optind;
  if (!*argv)
     return show_help();

  ctx.file_name = argv[0];
  ctx.callback  = csv_callback;

  rc = CSV_open_and_parse_file (&ctx);
  if (!rc)
     puts ("CSV_open_and_parse_file() failed!");

  return (rc == 0 ? 1 : 0);
}

/*
 * Function needed to support generated .c-files
 */
static NO_INLINE int CSV_cfile_open (struct CSV_context *ctx)
{
  CSV_cfile *h = &ctx->cfile;

  if (!h->file_name)
     return (1);

  h->field_sizes = calloc (ctx->num_fields * sizeof(size_t), 1);
  if (!h->field_sizes)
  {
    TRACE (1, "Failed to allocate data.\n");
    return (0);
  }

  if (!strcmp(h->file_name, "-"))
       h->file = stdout;
  else h->file = fopen (h->file_name, "wt");
  if (!h->file)
  {
    TRACE (1, "Failed to open file \"%s\". errno: %d\n", h->file_name, errno);
    free (h->field_sizes);
    h->field_sizes = NULL;
    h->file = NULL;
    return (0);
  }
  return (1);
}

static NO_INLINE void CSV_cfile_close (struct CSV_context *ctx)
{
  CSV_cfile *h = &ctx->cfile;
  char      *p, *prefix, *fname;
  char       comment [1000];
  time_t     now;
  unsigned   i;

  if (!h->file)
     return;

  if (h->file == stdout)
       fprintf (stderr, "Writing %s data to stdout.\n", ctx->file_name);
  else fprintf (stderr, "Writing %s data to %s.\n", ctx->file_name, h->file_name);

  now = time (NULL);
  snprintf (comment, sizeof(comment),
            "A generated .c-file representing the CSV data in '%s'.\n"
            " * Generated at %.24s by:\n"
            " * '%s'.\n"
            " *\n"
            " * DO NOT EDIT!",
            ctx->file_name, ctime(&now), GetCommandLine());

  prefix = strdup (basename(ctx->file_name));
  for (p = prefix; *p; p++)
  {
    if (!isalnum((int)*p) && !isdigit((int)*p))
       *p = '_';
  }

  fprintf (h->file,
           "/*\n"
           " * %s\n"
           " */\n"
           "#include <stdio.h>\n"
           "#include <stdlib.h>\n"
           "#include <stdbool.h>\n"
           "#include <string.h>\n"
           "#include <getopt.h>\n"
           "#include \"csv.h\"\n"
           "\n"
           "#pragma pack(push,1)\n"
           "typedef struct %s_gen_record {\n", comment, prefix);

  for (i = 0; i < ctx->num_fields; i++)
      fprintf (h->file, "        char field_%d [%zd];\n", i, h->field_sizes[i]);

  fprintf (h->file,
           "      } %s_gen_record;\n"
           "#pragma pack(pop)\n"
           "\n"
           "%s_gen_record *%s_data;\n"
           "size_t %*s_data_size;\n\n",
           prefix, prefix, prefix, 17+(int)strlen(prefix), prefix);

  fprintf (h->file,
           "#define %s_ALLOC_DATA(sz) CSV_generic_alloc ((void**)&%s_data, &%s_data_size, sz)\n"
           "#define %s_FREE_DATA()    CSV_generic_free ((void**)&%s_data, &%s_data_size)\n\n",
           prefix, prefix, prefix, prefix, prefix, prefix);

  fprintf (h->file, "#define %s_READ_BIN(fname) \\\n"
                    "        CSV_generic_read_bin (fname, (void**)&%s_data, &%s_data_size)\n\n",
           prefix, prefix, prefix);

  fprintf (h->file, "#define %s_WRITE_BIN(fname) \\\n"
                    "        CSV_generic_write_bin (fname, %s_data, %s_data_size, sizeof(%s_gen_record), 0)\n\n",
           prefix, prefix, prefix, prefix);

  fprintf (h->file, "#undef  FIELD_SIZE\n"
                    "#undef  FIELD_OFS\n");

  fprintf (h->file, "#define FIELD_SIZE(n) sizeof (((%s_gen_record *)0)->field_##n)\n", prefix);
  fprintf (h->file, "#define FIELD_OFS(n)  (size_t) &(((%s_gen_record *)0)->field_##n)\n\n", prefix);

  for (i = 0; i < ctx->num_fields; i++)
  {
    fprintf (h->file, "#define %s_GEN_DATA_%d(idx, value) \\\n", prefix, i);
    fprintf (h->file, "        CSV_generic_gen_data (%s_data, \\\n"
                      "                              %s_data_size, \\\n"
                      "                              sizeof(%s_gen_record), \\\n"
                      "                              idx, value, %d, FIELD_SIZE(%d))\n\n",
             prefix, prefix, prefix, i, i);
  }

  for (i = 0; i < ctx->num_fields; i++)
  {
    fprintf (h->file, "#define %s_LOOKUP_FIELD_%d(key) \\\n", prefix, i);
    fprintf (h->file, "        (%s_gen_record*) CSV_generic_lookup ( \\\n"
                      "          key, %zd, FIELD_OFS(%d), \\\n"
                      "          %s_data, %s_data_size, \\\n"
                      "          sizeof(%s_gen_record), %u, \\\n"
                      "          CSV_test_use_bsearch)\n\n",
             prefix, h->field_sizes[i], i, prefix, prefix, prefix, ctx->rec_num);
  }

  fname = strdup (ctx->file_name);
  str_replace ('\\', '/', fname);

  fprintf (h->file,
           "#if defined(CSV_TEST)\n"
           "\n"
           "static char *word_n (int n)\n"
           "{\n"
           "  static char word [20];\n"
           "  snprintf (word, sizeof(word), \"word-%%d\", n);\n"
           "  return (word);\n"
           "}\n"
           "\n"
           "static void usage (const char *argv0)\n"
           "{\n"
           "  printf (\"Usage: %%s [options]\\n\"\n"
           "          \"  -b: use bsearch().\\n\"\n"
           "          \"  -v: verbose mode.\\n\",\n"
           "          argv0);\n"
           "  exit (0);\n"
           "}\n"
           "\n"
           "int main (int argc, char **argv)\n"
           "{\n"
           "  int ch, i, i_max = %d;\n"
           "\n"
           "  while ((ch = getopt(argc, argv, \"bvh?\")) != EOF)\n"
           "     switch (ch)\n"
           "     {\n"
           "       case 'b':\n"
           "            CSV_test_use_bsearch = 1;\n"
           "            break;\n"
           "       case 'h':\n"
           "       case '?':\n"
           "            usage (argv[0]);\n"
           "            break;\n"
           "       case 'v':\n"
           "            CSV_test_trace = 1;\n"
           "            break;\n"
           "     }\n"
           "\n", ctx->rec_num);

  fprintf (h->file,
           "  %s_ALLOC_DATA (i_max * sizeof(%s_gen_record));\n",
           prefix, prefix);

  fprintf (h->file,
           "  for (i = 0; i < i_max; i++)\n"
           "      %s_GEN_DATA_0 (i, word_n(i));\n"
           "  %s_WRITE_BIN (\"%s.BIN\");\n"
           "  %s_FREE_DATA();\n\n",
           prefix, prefix, fname, prefix);

  fprintf (h->file,
           "  if (%s_READ_BIN(\"%s.BIN\") > 0)\n"
           "  {\n"
           "    %s_LOOKUP_FIELD_0 (\"word-1\");\n"
           "    %s_LOOKUP_FIELD_0 (\"word-2\");\n"
           "  }\n"
           "  return (0);\n"
           "}\n"
           "#endif /* CSV_TEST */\n",
           prefix, fname, prefix, prefix);

  if (h->file != stdout)
     fclose (h->file);
  h->file = NULL;
  free (prefix);
  free (fname);
  free (h->field_sizes);
}
#endif  /* !CSV_TEST */

int CSV_test_trace = 0;
int CSV_test_use_bsearch = 0;

#define CTRACE(level, fmt, ...) do { \
                                  if (CSV_test_trace >= level) \
                                     printf ("%s(%u): " fmt, __FILE__, __LINE__, ## __VA_ARGS__); \
                                } while (0)

#pragma pack(push,1)
typedef struct CSV_header {      /* 12  bytes */
        char      marker [4];    /* "CBIN" */
        uint32_t  rec_size;
        uint32_t  rec_numbers;
      } CSV_header;
#pragma pack(pop)

typedef struct generic_record {
        size_t  rec_size;
        size_t  field_size;
        char   *field_X;
      } generic_record;

void CSV_generic_alloc (void **data_p, size_t *data_size_p, size_t sz)
{
  void *data = calloc (sz, 1);

  *data_p = data;
  if (!data)
  {
    CTRACE (0, "Failed to allocate %zd bytes.\n", sz);
    sz = 0;
  }
  if (data_size_p)
     *data_size_p = sz;
}

void CSV_generic_free (void **data, size_t *sz)
{
  if (*data)
  {
    memset (*data, '\0', *sz);
    free (*data);
  }
  *data = NULL;
  *sz =0;
}

size_t CSV_generic_read_bin (const char *fname, void **data_p, size_t *data_size_p)
{
  CSV_header  header;
  size_t      read, data_size;
  void       *data;
  FILE       *bin;
  struct stat st;

  if (stat(fname, &st) != 0)
  {
    CTRACE (0, "Failed to stat() file \"%s\". errno: %d\n", fname, errno);
    return (0);
  }
  st.st_size -= sizeof(header);

  bin = CSV_fopen_excl (fname, "rb");
  if (!bin)
  {
    CTRACE (0, "Failed to open file \"%s\". errno: %d\n", fname, errno);
    return (0);
  }

  *data_p      = NULL;
  *data_size_p = 0;

  memset (&header, '\0', sizeof(header));
  read = fread (&header, 1, sizeof(header), bin);
  if (read != sizeof(header) || memcmp(&header.marker, "CBIN", sizeof(header.marker)))
  {
    CTRACE (0, "Failed to read header; len %zd. errno: %d\n", read, errno);
    fclose (bin);
    return (0);
  }

  if (header.rec_numbers == 0 || header.rec_size == 0)
  {
    CTRACE (0, "File %s has zero records!\n", fname);
    fclose (bin);
    return (0);
  }

  data_size = header.rec_numbers * header.rec_size;
  CSV_generic_alloc (&data, NULL, data_size);
  if (!data)
  {
    fclose (bin);
    return (0);
  }

  read = fread (data, 1, data_size, bin);
  if (read != data_size || read != st.st_size)
  {
    CTRACE (0, "Failed to read all data; len %zd. errno: %d\n", read, errno);
    CSV_generic_free (&data, &data_size);
    fclose (bin);
    return (0);
  }

  fclose (bin);

  *data_p      = data;
  *data_size_p = data_size;

  CTRACE (1, "Read data for %u records of %u bytes each. data_size: %zd.\n",
          header.rec_numbers, header.rec_size, data_size);
  return (data_size);
}

size_t CSV_generic_write_bin (const char *fname, const void *data, size_t data_size, size_t rec_size, int overwrite)
{
  CSV_header header;
  size_t     wrote;
  FILE      *bin;

  if (!data || data_size == 0)
  {
    CTRACE (0, "data == NULL!\n");
    return (0);
  }

  if (overwrite == 0 && access(fname, 0) == 0)
  {
    CTRACE (0, "Not over-writing file \"%s\".\n", fname);
    return (0);
  }

  bin = CSV_fopen_excl (fname, "w+b");
  if (!bin)
  {
    CTRACE (0, "Failed to open file \"%s\". errno: %d\n", fname, errno);
    return (0);
  }

  memset (&header, '\0', sizeof(header));
  memcpy (&header.marker, "CBIN", sizeof(header.marker));
  header.rec_size    = (uint32_t) rec_size;
  header.rec_numbers = (uint32_t) (data_size / rec_size);

  wrote = fwrite (&header, 1, sizeof(header), bin);
  if (wrote != sizeof(header))
  {
    CTRACE (0, "Failed to write header; len %zd. errno: %d\n", wrote, errno);
    fclose (bin);
    return (0);
  }

  wrote = fwrite (data, 1, (unsigned int)data_size, bin);
  if (wrote != data_size)
  {
    CTRACE (0, "Failed to write all data; len %zd. errno: %d\n", wrote, errno);
    fclose (bin);
    return (0);
  }
  CTRACE (1, "Wrote data for %u records of %u bytes each.\n", header.rec_numbers, header.rec_size);
  fclose (bin);
  return (data_size);
}

unsigned CSV_generic_gen_data (void *data, size_t data_size,
                               size_t rec_size, unsigned idx,
                               const char *key, int key_ofs, int key_size)
{
  char *p, *p_max;

  if (!data)
  {
    CTRACE (0, "data == NULL!\n");
    return (0);
  }

  p     = ((char*) data) + (idx * rec_size) + key_ofs;
  p_max = ((char*) data) + data_size - key_size;
  if (p >= p_max)
  {
    CTRACE (0, "p >= p_max!!\n");
    return (0);
  }

  strncpy (p, key, key_size);
  CTRACE (1, "Wrote a %d byte key (\"%s\") to idx: %u, key_ofs: %d\n", key_size, key, idx, key_ofs);
  return (key_size);
}

static int bsearch_round = 0;

static int bsearch_helper (const void *a, const void *b)
{
  const char           *key    = (const char*) a;
  const generic_record *member = (const generic_record*) b;
  int   rc;

  CTRACE (1, "round: %d, key: '%s'.\n", bsearch_round++, key);
  rc = memcmp (key, member->field_X, member->field_size);

  CTRACE (1, "rc: %d.\n", rc);
  return (rc);
}

void *CSV_generic_lookup (const char *key, size_t key_size, int key_ofs,
                          void *data, size_t data_size, size_t rec_size,
                          size_t max_records, int use_bsearch)
{
  char *p, *p_max;
  int   i, found = 0;

  if (!data || data_size == 0)
  {
    CTRACE (1, "data == NULL!\n");
    return (0);
  }

  if (data_size != rec_size * max_records)
  {
    CTRACE (1, "data_size: %zu. rec_size * max_records: %zd.\n", data_size, rec_size * max_records);
    return (0);
  }

  p     = ((char*) data) + key_ofs;
  p_max = ((char*) data) + data_size;

/*
  #define IP4_ASN_CSV_LOOKUP_FIELD_0(key)           \
          CSV_generic_lookup (key, 9, FIELD_OFS(0), \
                              IP4_ASN_CSV_data, IP4_ASN_CSV_data_size, sizeof(*IP4_ASN_CSV_data), 100, CSV_test_use_bsearch)
 */

  if (CSV_test_use_bsearch)
  {
    generic_record rec;

    rec.rec_size   = rec_size;
    rec.field_X    = p;
    rec.field_size = key_size;
    bsearch_round  = 0;
    CTRACE (0, "Using bsearch(): looking for key: '%s' in %zu records.\n", key, max_records);
    return bsearch (key, &rec, max_records, sizeof(rec), bsearch_helper);
  }

  CTRACE (0, "No bsearch(): Looking for key: '%s' at ofs: %d.\n", key, key_ofs);
  for (i = 0; i < max_records; i++)
  {
    CTRACE (1, "i: %d, p: '%.10s'\n", i, p);
    if (p >= p_max)
    {
      CTRACE (0, "p >= p_max!!\n");
      break;
    }
    found = (strncmp (key, p, key_size) == 0);
    if (found)
    {
      CTRACE (0, "key '%s' found in record %d.\n", key, i);
      return (p);
    }
    p += rec_size;
  }
  CTRACE (1, "key '%s' not found in %zd records.\n", key, max_records);
  return (NULL);
}

/**
 * Copied from 'common.c'
 */
FILE *CSV_fopen_excl (const char *file, const char *mode)
{
#if defined(__CYGWIN__)
  return fopen (file, mode);
#else
  int fd, open_flags, share_flags;

  switch (*mode)
  {
    case 'r':
          open_flags  = _O_RDONLY;
          share_flags = S_IREAD;
          break;
    case 'w':
          open_flags  = _O_WRONLY;
          share_flags = S_IWRITE;
          break;
    case 'a':
          open_flags  = _O_CREAT | _O_WRONLY | _O_APPEND;
          share_flags = S_IWRITE;
          break;
    default:
          return (NULL);
  }

  if (mode[1] == '+')
     open_flags |= _O_CREAT | _O_TRUNC;

  if (mode[strlen(mode)-1] == 'b')
     open_flags |= O_BINARY;

#ifdef _O_SEQUENTIAL
  open_flags |= _O_SEQUENTIAL;
#endif

#ifndef SH_DENYWR
#define SH_DENYWR  0x20   /* In <share.h> on MinGW */
#endif

  fd = _sopen (file, open_flags, SH_DENYWR, share_flags);
  if (fd <= -1)
     return (NULL);
  return fdopen (fd, mode);
#endif  /* __CYGWIN__ */
}


