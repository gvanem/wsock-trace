/*
 * idna.c - Part of Wsock-Trace.
 *
 * Code for enabling lookup of names with non-ASCII letters via
 * ACE and IDNA (Internationalizing Domain Names in Applications)
 * Ref. RFC-3490.
 */

/* Do not pull in <winsock.h> in <windows.h>
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* Because of warning "Use getaddrinfo() or GetAddrInfoW() instead ..."
 */
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <assert.h>
#include <windows.h>

#include "common.h"
#include "init.h"
#include "smartlist.h"
#include "idna.h"

#ifndef USE_WINIDN
#define USE_WINIDN 1
#endif

int _idna_winnls_errno = 0;
int _idna_errno = 0;

static BOOL         using_winidn = FALSE;
static UINT         cur_cp = CP_ACP;
static smartlist_t *cp_list;

#if (USE_WINIDN)
  typedef int (WINAPI *func_IdnToAscii) (DWORD          flags,
                                         const wchar_t *unicode_chars,
                                         int            unicode_len,
                                         wchar_t       *ASCII_chars,
                                         int            ASCII_len);

  typedef int (WINAPI *func_IdnToUnicode) (DWORD          flags,
                                           const wchar_t *ASCII_chars,
                                           int            ASCII_len,
                                           wchar_t       *unicode_chars,
                                           int            unicode_len);

  static func_IdnToAscii   p_IdnToAscii = NULL;
  static func_IdnToUnicode p_IdnToUnicode = NULL;

  #define ADD_VALUE(dll, func)  { 1, NULL, dll, #func, (void**)&p_##func }

  static struct LoadTable dyn_funcs [] = {
                ADD_VALUE ("normaliz.dll", IdnToAscii),
                ADD_VALUE ("normaliz.dll", IdnToUnicode),
                ADD_VALUE ("kernel32.dll", IdnToAscii),
                ADD_VALUE ("kernel32.dll", IdnToUnicode)
              };
#endif

/*
 * Structure used in 'get_cp_info()' and 'EnumSystemCodePages()'.
 */
typedef struct code_page_info {
        UINT  number;
        char  name [100];
        BOOL  valid;
      } code_page_info;

/*
 * punycode from RFC 3492
 * http://www.nicemice.net/idn/
 * Adam M. Costello
 * http://www.nicemice.net/amc/
 */
typedef enum punycode_status {
        punycode_success,
        punycode_bad_input,      /* Input is invalid.                       */
        punycode_big_output,     /* Output would exceed the space provided. */
        punycode_overflow        /* Input needs wider integers to process.  */
      } punycode_status;

/*
 * punycode_encode() converts Unicode to Punycode.  The input
 * is represented as an array of Unicode code points (not code
 * units; surrogate pairs are not allowed), and the output
 * will be represented as an array of ASCII code points.  The
 * output string is *not* null-terminated; it will contain
 * zeros if and only if the input contains zeros.  (Of course
 * the caller can leave room for a terminator and add one if
 * needed.)  The input_length is the number of code points in
 * the input.  The output_length is an in/out argument: the
 * caller passes in the maximum number of code points that it
 * can receive, and on successful return it will contain the
 * number of code points actually output.  The case_flags array
 * holds input_length boolean values, where nonzero suggests that
 * the corresponding Unicode character be forced to uppercase
 * after being decoded (if possible), and zero suggests that
 * it be forced to lowercase (if possible).  ASCII code points
 * are encoded literally, except that ASCII letters are forced
 * to uppercase or lowercase according to the corresponding
 * uppercase flags.  If case_flags is a null pointer then ASCII
 * letters are left as they are, and other code points are
 * treated as if their uppercase flags were zero.  The return
 * value can be any of the punycode_status values defined above
 * except punycode_bad_input; if not punycode_success, then
 * output_size and output might contain garbage.
 */
static enum punycode_status punycode_encode (size_t       input_length,
                                             const DWORD *input,
                                             const BYTE  *case_flags,
                                             size_t      *output_length,
                                             char        *output);

/*
 * punycode_decode() converts Punycode to Unicode.  The input is
 * represented as an array of ASCII code points, and the output
 * will be represented as an array of Unicode code points.  The
 * input_length is the number of code points in the input.  The
 * output_length is an in/out argument: the caller passes in
 * the maximum number of code points that it can receive, and
 * on successful return it will contain the actual number of
 * code points output.  The case_flags array needs room for at
 * least output_length values, or it can be a null pointer if the
 * case information is not needed.  A nonzero flag suggests that
 * the corresponding Unicode character be forced to uppercase
 * by the caller (if possible), while zero suggests that it be
 * forced to lowercase (if possible).  ASCII code points are
 * output already in the proper case, but their flags will be set
 * appropriately so that applying the flags would be harmless.
 * The return value can be any of the punycode_status values
 * defined above; if not punycode_success, then output_length,
 * output, and case_flags might contain garbage.  On success, the
 * decoder will never need to write an output_length greater than
 * input_length, because of how the encoding is defined.
 */
static enum punycode_status punycode_decode (size_t      input_length,
                                             const char *input,
                                             size_t     *output_length,
                                             DWORD      *output,
                                             BYTE       *case_flags);

/*
 * The following string is used to convert printable
 * Punycode characters to ASCII:
 */
static const char print_ascii[] = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
                                  "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
                                  " !\"#$%&'()*+,-./"
                                  "0123456789:;<=>?"
                                  "@ABCDEFGHIJKLMNO"
                                  "PQRSTUVWXYZ[\\]^_"
                                  "`abcdefghijklmno"
                                  "pqrstuvwxyz{|}~\n";

/*
 * Get ANSI/system codepage.
 */
UINT IDNA_GetCodePage (void)
{
  CPINFOEX CPinfo;
  UINT     CP = 0;

  TRACE (3, "OEM codepage %u\n", GetOEMCP());
  CP = GetACP();

  if (GetCPInfoEx(CP, 0, &CPinfo))
     TRACE (3, "ACP-name %s\n", CPinfo.CodePageName);
  return (CP);
}

/*
 * Callback for EnumSystemCodePages()
 */
static BOOL CALLBACK get_cp_info (LPTSTR cp_str)
{
  UINT            cp = atoi (cp_str);
  CPINFOEX        cp_info_ex;
  code_page_info *cp_info = calloc (1, sizeof(*cp_info));

  cp_info->number = cp;
  cp_info->valid  = IsValidCodePage (cp);

  if (GetCPInfoEx(cp, 0, &cp_info_ex))
     _strlcpy (cp_info->name, cp_info_ex.CodePageName, sizeof(cp_info->name));

  smartlist_add (cp_list, cp_info);
  return (TRUE);
}

/*
 * smartlist_sort() helper: return -1, 1, or 0.
 */
static int cp_compare (const void **_a, const void **_b)
{
  const code_page_info *a = *_a;
  const code_page_info *b = *_b;

  return ((int)a->number - (int)b->number);
}

/*
 * Check if given codepage is available
 */
BOOL IDNA_CheckCodePage (UINT cp)
{
  code_page_info *cp_info;
  BOOL            cp_found = FALSE;
  int             i, max;

  cp_list = smartlist_new();

  EnumSystemCodePages (get_cp_info, CP_INSTALLED);

  smartlist_sort (cp_list, cp_compare);
  max = smartlist_len (cp_list);

  TRACE (3, "%d Built-in CodePages:\n", max);

  for (i = 0; i < max; i++)
  {
    char mark = ' ';

    cp_info = smartlist_get (cp_list, i);
    if (cp_info->valid && cp_info->number == cp)
    {
      mark = '!';
      cp_found = TRUE;
    }
    if (cp_info->name[0])
         TRACE (3, "%cCP-name: %s\n", mark, cp_info->name);
    else TRACE (3, "%cCP-name: %-5u <unknown>\n", mark, cp_info->number);
  }

  /* And now free the 'cp_list'
   */
  for (i = 0; i < max; i++)
  {
    cp_info = smartlist_get (cp_list, i);
    free (cp_info);
  }
  smartlist_free (cp_list);
  cp_list = NULL;
  return (cp_found);
}

void IDNA_exit (void)
{
#if (USE_WINIDN)
  if (using_winidn)
     unload_dynamic_table (dyn_funcs, DIM(dyn_funcs));
#endif
}

/*
 * Get active codpage and optionally initialise WinIDN.
 */
BOOL IDNA_init (WORD cp, BOOL use_winidn)
{
#if (USE_WINIDN)
  if (use_winidn)
  {
    int num = load_dynamic_table (dyn_funcs, DIM(dyn_funcs));

    TRACE (3, "load_dynamic_table() -> %d\n", num);
    if (num < 2)
    {
      unload_dynamic_table (dyn_funcs, DIM(dyn_funcs));
      return (FALSE);
    }
    using_winidn = TRUE;
  }
#endif

  if (cp == 0)
     cp = IDNA_GetCodePage();

  if (!IDNA_CheckCodePage(cp))
  {
    _idna_errno = IDNAERR_ILL_CODEPAGE;
    _idna_winnls_errno = GetLastError();
    TRACE (0, "IDNA_init: %s\n", IDNA_strerror(_idna_errno));
    return (FALSE);
  }
  cur_cp = cp;
  TRACE (3, "IDNA_init: Using codepage %u\n", cp);
  return (TRUE);
}

/*
 * Return FALSE if 'name' is not a plain US-ASCII name.
 * Thus need to call 'IDNA_convert_to_ACE()'.
 */
BOOL IDNA_is_ASCII (const char *name)
{
  const BYTE *ch = (const BYTE*) name;

  while (*ch)
  {
    if (*ch++ & 0x80)
       return (FALSE);
  }
  return (TRUE);
}

const char *IDNA_strerror (int err)
{
  static char buf[200];

  switch ((enum IDNA_errors)err)
  {
    case IDNAERR_OK:
         return ("No error");
    case IDNAERR_NOT_INIT:
         return ("Not initialised");
    case IDNAERR_PUNYCODE_BASE:
         return ("No Punycode error");
    case IDNAERR_PUNYCODE_BAD_INPUT:
         return ("Bad Punycode input");
    case IDNAERR_PUNYCODE_BIG_OUTBUF:
         return ("Punycode output buf too small");
    case IDNAERR_PUNYCODE_OVERFLOW:
         return ("Punycode arithmetic overflow");
    case IDNAERR_PUNY_ENCODE:
         return ("Mysterious Punycode encode result");
    case IDNAERR_ILL_CODEPAGE:
         return ("Illegal or no Codepage defined");
    case IDNAERR_WINNLS:
         return win_strerror (_idna_winnls_errno);
  }
  sprintf (buf, "Unknown %d", err);
  return (buf);
}

/*
 * Convert a single ASCII codepoint from active codepage to Unicode.
 */
static BOOL conv_to_unicode (char ch, wchar_t *wc)
{
  int rc = MultiByteToWideChar (cur_cp, 0, (LPCSTR)&ch, 1, wc, 1);

  if (rc == 0)
  {
    _idna_winnls_errno = GetLastError();
    _idna_errno = IDNAERR_WINNLS;
    TRACE (2, "conv_to_unicode failed; %s\n", IDNA_strerror(IDNAERR_WINNLS));
    return (FALSE);
  }
  return (TRUE);
}

/*
 * Convert a single Unicode codepoint to ASCII in active codepage.
 * Allow 4 byte GB18030 Simplified Chinese to be converted.
 */
static BOOL conv_to_ascii (wchar_t wc, char *ch, int *len)
{
  int rc = WideCharToMultiByte (cur_cp, 0, &wc, 1, (LPSTR)ch, 4, NULL, NULL);

  if (rc == 0)
  {
    _idna_winnls_errno = GetLastError();
    _idna_errno = IDNAERR_WINNLS;
    TRACE (2, "conv_to_ascii failed; %s\n", IDNA_strerror(IDNAERR_WINNLS));
    return (FALSE);
  }
  *len = rc;
  return (TRUE);
}

/*
 * Split a domain-name into labels (no trailing dots)
 */
static char **split_labels (const char *name)
{
  static char  buf [MAX_HOST_LABELS][MAX_HOST_LEN];
  static char *res [MAX_HOST_LABELS+1];
  const  char *p = name;
  int    i;

  for (i = 0; i < MAX_HOST_LABELS && *p; i++)
  {
    const char *dot = strchr (p, '.');

    if (!dot)
    {
      res[i] = _strlcpy (buf[i], p, sizeof(buf[i]));
      i++;
      break;
    }
    res[i] = _strlcpy (buf[i], p, dot-p+1);
    p = ++dot;
  }
  res[i] = NULL;
  TRACE (3, "split_labels: `%s', %d labels\n", name, i);
  return (res);
}

/*
 * Convert a single label to ACE form
 */
static char *convert_to_ACE (const char *name)
{
  static char out_buf [2*MAX_HOST_LEN];  /* A conservative guess */
  DWORD  ucs_input [MAX_HOST_LEN];
  BYTE   ucs_case [MAX_HOST_LEN];
  const  char *p;
  size_t in_len, out_len;
  int    i, c;
  punycode_status status;

  for (i = 0, p = name; *p; i++)
  {
    wchar_t ucs = 0;

    c = *p++;
    if (!conv_to_unicode (c, &ucs))
       return (NULL);
    ucs_input[i] = ucs;
    ucs_case[i]  = 0;
    TRACE (3, "%c -> u+%04X\n", c, ucs);
  }
  in_len  = i;
  out_len = sizeof(out_buf);
  status  = punycode_encode (in_len, ucs_input, ucs_case, &out_len, out_buf);

  if (status != punycode_success)
  {
    _idna_errno = IDNAERR_PUNYCODE_BASE + status;
    out_len = 0;
  }

  for (i = 0; i < (int)out_len; i++)
  {
    c = out_buf[i];
    if (c < 0 || c > 127)
    {
      _idna_errno = IDNAERR_PUNY_ENCODE;
      TRACE (2, "illegal Punycode result: %c (%d)\n", c, c);
      break;
    }
    if (!print_ascii[c])
    {
      _idna_errno = IDNAERR_PUNY_ENCODE;
      TRACE (2, "Punycode not ASCII: %c (%d)\n", c, c);
      break;
    }
    out_buf[i] = print_ascii[c];
  }
  out_buf[i] = '\0';

  TRACE (3, "punycode_encode: status %d, out_len %u, out_buf `%s'\n",
         status, (unsigned)out_len, out_buf);
  if (status == punycode_success && i == (int)out_len)   /* encoding and ASCII conversion okay */
     return (out_buf);
  return (NULL);
}

/*
 * Convert a single ACE encoded label to native encoding
 * u+XXXX is used to signify a lowercase character.
 * U+XXXX is used to signify a uppercase character.
 * Normally only lowercase should be expected here.
 */
static char *convert_from_ACE (const char *name)
{
  static char out_buf [MAX_HOST_LEN];
  DWORD  ucs_output [MAX_HOST_LEN];
  BYTE   ucs_case  [MAX_HOST_LEN];
  size_t ucs_len, i, j;
  punycode_status status;

  memset (&ucs_case, '\0', sizeof(ucs_case));
  ucs_len = sizeof(ucs_output);
  status = punycode_decode (strlen(name), name, &ucs_len, ucs_output, ucs_case);

  if (status != punycode_success)
  {
    _idna_errno = IDNAERR_PUNYCODE_BASE + status;
    ucs_len = 0;
  }

  for (i = j = 0; i < ucs_len && j < sizeof(out_buf)-4; i++)
  {
    wchar_t ucs = (wchar_t) ucs_output[i];
    int     len;

    if (!conv_to_ascii(ucs, out_buf+j, &len))
       return (NULL);
    TRACE (3, "%c+%04X -> %.*s\n",
                ucs_case[i] ? 'U' : 'u', ucs, len, out_buf+j);
    j += len;
  }
  out_buf[j] = '\0';
  TRACE (3, "punycode_decode: status %d, out_len %u, out_buf `%s'\n",
         status, (unsigned)ucs_len, out_buf);
  return (status == punycode_success ? out_buf : NULL);
}

#if (USE_WINIDN && 0)
/*
 * Taken from libcurl's idn_win32.c and rewritten.
 */
static BOOL win32_idn_to_ascii (const char *in, char **out)
{
  BOOL     rc = FALSE;
  wchar_t *in_w = Curl_convert_UTF8_to_wchar (in);

  if (in_w)
  {
    wchar_t punycode [IDN_MAX_LENGTH];
    int     chars = (*p_IdnToAscii) (0, in_w, -1, punycode, DIM(punycode));

    free (in_w);
    if (chars)
    {
      *out = Curl_convert_wchar_to_UTF8 (punycode);
      if (*out)
         rc = TRUE;
    }
  }
  return (rc);
}

static BOOL win32_ascii_to_idn (const char *in, char **out)
{
  BOOL     rc   = FALSE;
  wchar_t *in_w = Curl_convert_UTF8_to_wchar (in);

  if (in_w)
  {
    size_t  in_len = wcslen (in_w) + 1;
    wchar_t unicode [IDN_MAX_LENGTH];
    int     chars = (*p_IdnToUnicode) (0, in_w, curlx_uztosi(in_len),
                                       unicode, DIM(unicode));
    free (in_w);
    if (chars)
    {
      *out = Curl_convert_wchar_to_UTF8 (unicode);
      if (*out)
         rc = TRUE;
    }
  }
  return (rc);
}
#endif  /* (USE_WINIDN && 0) */

/*
 * E.g. convert "www.tromsø.no" to ACE:
 *
 * 1) Convert each label separately. "www", "tromsø" and "no"
 * 2) "tromsø" -> u+0074 u+0072 u+006F u+006D u+0073 u+00F8
 * 3) Pass this through `punycode_encode()' which gives "troms-zua".
 * 4) Repeat for all labels with non-ASCII letters.
 * 5) Prepending "xn--" for each converted label gives "www.xn--troms-zua.no".
 *
 * E.g. 2:
 *   "www.blåbærsyltetøy.no" -> "www.xn--blbrsyltety-y8aO3x.no"
 *
 * Ref. http://www.imc.org/idna/do-idna.cgi
 *      http://www.norid.no/domenenavnbaser/ace/ace_technical.en.html
 */
BOOL IDNA_convert_to_ACE (
          char   *name,   /* IN/OUT: native ASCII/ACE name */
          size_t *size)   /* IN:     length of name buf */
{                         /* OUT:    ACE encoded length */
  const  BYTE *p;
  const  char *ace;
  char  *in_name = name;
  char **labels;
  int    i;
  size_t len = 0;
  BOOL   rc = FALSE;

#if (USE_WINIDN && 0)
  if (using_winidn)
     return win32_idn_to_ascii (name, size);
#endif

  labels = split_labels (name);

  for (i = 0; labels[i]; i++)
  {
    const char *label = labels[i];

    ace = NULL;
    if (!strncmp("xn--", label, 4))
    {
      TRACE (2, "IDNA_convert_to_ACE: label `%s' already prefixed\n", label);
      goto quit;
    }
    for (p = (const BYTE*)label; *p; p++)
    {
      if (*p >= 0x80)
      {
        ace = convert_to_ACE (label);
        if (!ace)
           goto quit;
        break;
      }
    }

    if (ace)
    {
      if (len + 5 + strlen(ace) > *size)
      {
        TRACE (2, "input length exceeded\n");
        goto quit;
      }
      name += sprintf (name, "xn--%s.", ace);
    }
    else  /* pass through unchanged */
    {
      if (len + 1 + strlen(label) > *size)
      {
        TRACE (2, "input length exceeded\n");
        goto quit;
      }
      name += sprintf (name, "%s.", label);
    }
  }
  if (in_name > name)   /* drop trailing '.' */
     name--;
  len = name - in_name;
  *name = '\0';
  *size = len;
  TRACE (3, "IDNA_convert_to_ACE: `%s', %u bytes\n", in_name, (unsigned)len);
  rc = TRUE;

quit:
  return (rc);
}

/*
 * 1) Pass through labels w/o "xn--" prefix unaltered.
 * 2) Strip "xn--" prefix and pass to punycode_decode()
 * 3) Repeat for all labels with "xn--" prefix.
 * 4) Collect Unicode strings and convert to original codepage.
 */
BOOL IDNA_convert_from_ACE (
          char   *name,    /* IN/OUT: ACE/native ASCII name */
          size_t *size)    /* IN:     ACE raw string length */
{                          /* OUT:    ASCII decoded length */
  char  *in_name = name;
  char **labels;
  int    i;
  BOOL   rc = FALSE;

#if (USE_WINIDN && 0)
  if (using_winidn)
     return win32_ascii_to_idn (name, size);
#endif

  labels  = split_labels (name);

  for (i = 0; labels[i]; i++)
  {
    const char *ascii = NULL;
    const char *label = labels[i];

    if (!strncmp(label,"xn--",4) && label[4])
    {
      ascii = convert_from_ACE (label+4);
      if (!ascii)
         goto quit;
    }
    name += sprintf (name, "%s.", ascii ? ascii : label);
  }
  if (name > in_name)
     name--;
  *name = '\0';
  *size = name - in_name;
  rc = TRUE;

quit:
  return (rc);
}

/*
 * Bootstring parameters for Punycode
 */
enum {
  base = 36, tmin = 1, tmax = 26,
  skew = 38, damp = 700,
  initial_bias = 72,
  initial_n = 0x80,
  delimiter = 0x2D
};

/* basic(cp) tests whether cp is a basic code point:
 */
#define basic(cp) ((DWORD)(cp) < 0x80)

/* delim(cp) tests whether cp is a delimiter:
 */
#define delim(cp) ((cp) == delimiter)

/*
 * decode_digit(cp) returns the numeric value of a basic code
 * point (for use in representing integers) in the range 0 to
 * base-1, or base if cp is does not represent a value.
 */
static DWORD decode_digit (DWORD cp)
{
  return (cp - 48 < 10 ?
          cp - 22 : cp - 65 < 26 ?
          cp - 65 : cp - 97 < 26 ?
          cp - 97 : base);
}

/*
 * encode_digit(d,flag) returns the basic code point whose value
 * (when used for representing integers) is d, which needs to be in
 * the range 0 to base-1.  The lowercase form is used unless flag is
 * nonzero, in which case the uppercase form is used.  The behavior
 * is undefined if flag is nonzero and digit d has no uppercase form.
 */
static char encode_digit (DWORD d, int flag)
{
  return (char) (d + 22 + 75 * (d < 26) - ((flag != 0) << 5));
  /*  0..25 map to ASCII a..z or A..Z */
  /* 26..35 map to ASCII 0..9         */
}

/* flagged(bcp) tests whether a basic code point is flagged
 * (uppercase).  The behavior is undefined if bcp is not a
 * basic code point.
 */
#define flagged(bcp) ((DWORD)(bcp) - 65 < 26)

/*
 * encode_basic(bcp,flag) forces a basic code point to lowercase
 * if flag is zero, uppercase if flag is nonzero, and returns
 * the resulting code point.  The code point is unchanged if it
 * is caseless.  The behavior is undefined if bcp is not a basic
 * code point.
 */
static char encode_basic (DWORD bcp, int flag)
{
  bcp -= (bcp - 97 < 26) << 5;
  return (char) (bcp + ((!flag && (bcp - 65 < 26)) << 5));
}

/* maxint is the maximum value of a DWORD variable:
 */
static const DWORD maxint = (DWORD)-1;

static DWORD adapt (DWORD delta, DWORD numpoints, int firsttime)
{
  DWORD k;

  delta = firsttime ? delta / damp : delta >> 1;
  /* delta >> 1 is a faster way of doing delta / 2
   */
  delta += delta / numpoints;

  for (k = 0; delta > ((base - tmin) * tmax) / 2; k += base)
      delta /= base - tmin;
  return k + (base - tmin + 1) * delta / (delta + skew);
}

/*
 * Main encode function
 */
static enum punycode_status punycode_encode (size_t       input_length,
                                             const DWORD *input,
                                             const BYTE  *case_flags,
                                             size_t      *output_length,
                                             char        *output)
{
  DWORD n, delta, h, b, out, max_out;
  DWORD bias, j, m, q, k, t;

  /* Initialize the state:
   */
  n = initial_n;
  delta = out = 0;
  max_out = *(DWORD*)output_length;
  bias = initial_bias;

  /* Handle the basic code points:
   */
  for (j = 0; j < input_length; ++j)
  {
    if (basic (input[j]))
    {
      if (max_out - out < 2)
         return (punycode_big_output);
      output[out++] = case_flags ? encode_basic (input[j], case_flags[j]) :
                                   (char)input[j];
    }
#if 0
    else if (input[j] < n)
         return (punycode_bad_input);
    /* (not needed for Punycode with unsigned code points) */
#endif
  }

  h = b = out;

  /* h is the number of code points that have been handled, b is the
   * number of basic code points, and out is the number of characters
   * that have been output.
   */
  if (b > 0)
     output[out++] = delimiter;

  /* Main encoding loop:
   */
  while (h < input_length)
  {
    /* All non-basic code points < n have been
     * handled already.  Find the next larger one:
     */
    for (m = maxint, j = 0; j < input_length; ++j)
    {
#if 0
      if (basic(input[j]))
          continue;
      /* (not needed for Punycode) */
#endif
      if (input[j] >= n && input[j] < m)
         m = input[j];
    }

    /* Increase delta enough to advance the decoder's
     * <n,i> state to <m,0>, but guard against overflow:
     */
    if (m - n > (maxint - delta) / (h + 1))
       return (punycode_overflow);

    delta += (m - n) * (h + 1);
    n = m;

    for (j = 0; j < input_length; ++j)
    {
      if (input[j] < n)
      {
        if (++delta == 0)
           return (punycode_overflow);
      }

      if (input[j] == n)
      {
        /* Represent delta as a generalized variable-length integer:
         */
        for (q = delta, k = base;; k += base)
        {
          if (out >= max_out)
             return (punycode_big_output);

          t = k <= bias ? tmin :
              k >= bias + tmax ? tmax :
              k - bias;
          if (q < t)
             break;
          output[out++] = encode_digit (t + (q - t) % (base - t), 0);
          q = (q - t) / (base - t);
        }
        output[out++] = encode_digit (q, case_flags && case_flags[j]);
        bias = adapt (delta, h + 1, h == b);
        delta = 0;
        ++h;
      }
    }
    ++delta;
    ++n;
  }

  *output_length = out;
  return (punycode_success);
}

/*
 * Main decode function
 */
static enum punycode_status punycode_decode (size_t      input_length,
                                             const char *input,
                                             size_t      *output_length,
                                             DWORD       *output,
                                             BYTE        *case_flags)
{
  DWORD n, out, i, max_out, bias, b, j, in, oldi, w, k, digit, t;

  /* Initialize the state: */

  n = initial_n;
  out = i = 0;
  max_out = *(DWORD*) output_length;
  bias = initial_bias;

  /* Handle the basic code points:  Let b be the number of input code
   * points before the last delimiter, or 0 if there is none, then
   * copy the first b code points to the output.
   */
  for (b = j = 0; j < input_length; ++j)
      if (delim (input[j]))
         b = j;
  if (b > max_out)
     return (punycode_big_output);

  for (j = 0; j < b; ++j)
  {
    if (case_flags)
       case_flags[out] = flagged (input[j]);
    if (!basic (input[j]))
       return (punycode_bad_input);
    output[out++] = input[j];
  }

  /* Main decoding loop:  Start just after the last delimiter if any
   * basic code points were copied; start at the beginning otherwise.
   */
  for (in = b > 0 ? b + 1 : 0; in < input_length; ++out)
  {
    /* in is the index of the next character to be consumed, and
     * out is the number of code points in the output array.
     */

    /* Decode a generalized variable-length integer into delta,
     * which gets added to i.  The overflow checking is easier
     * if we increase i as we go, then subtract off its starting
     * value at the end to obtain delta.
     */
    for (oldi = i, w = 1, k = base;; k += base)
    {
      if (in >= input_length)
         return (punycode_bad_input);

      digit = decode_digit (input[in++]);
      if (digit >= base)
         return (punycode_bad_input);

      if (digit > (maxint - i) / w)
         return (punycode_overflow);

      i += digit * w;
      t = k <= bias ? tmin :
          k >= bias + tmax ? tmax :
          k - bias;
      if (digit < t)
         break;
      if (w > maxint / (base - t))
         return (punycode_overflow);

      w *= (base - t);
    }

    bias = adapt (i - oldi, out + 1, oldi == 0);

    /* i was supposed to wrap around from out+1 to 0,
     * incrementing n each time, so we'll fix that now:
     */
    if (i / (out + 1) > maxint - n)
       return (punycode_overflow);

    n += i / (out + 1);
    i %= (out + 1);

    /* Insert n at position i of the output:
     */
#if 0
    /* not needed for Punycode: */
    if (decode_digit(n) <= base)
       return (punycode_invalid_input);
#endif
    if (out >= max_out)
       return (punycode_big_output);

    if (case_flags)
    {
      memmove (case_flags + i + 1, case_flags + i, out - i);

      /* Case of last character determines uppercase flag:
       */
      case_flags[i] = flagged (input[in - 1]);
    }
    memmove (output + i + 1, output + i, (out - i) * sizeof *output);
    output[i++] = n;
  }

  *output_length = out;
  return (punycode_success);
}

#if defined(TEST_IDNA)

#include "getopt.h"

struct config_table g_cfg;

#if (USE_WINIDN)
  #define W_GETOPT "w"
  #define W_OPT    "[-w] "
  #define W_HELP   "   -w use the Windows Idn functions\n"
#else
  #define W_GETOPT ""
  #define W_OPT    ""
  #define W_HELP   ""
#endif

void usage (const char *argv0)
{
  printf ("%s [-d] %s[-c CP-number] hostname | ip-address\n"
          "   -d debug level, \"-dd\" for more details\n"
          "%s"
          "   -c select codepage (active is CP%d)\n",
          argv0, W_OPT, W_HELP, IDNA_GetCodePage());
  exit (0);
}

void set_color (const WORD *col)
{
  ARGSUSED (col);
}

void ws_sema_wait (void)
{
}

void ws_sema_release (void)
{
}

void print_last_error (void)
{
  printf ("IDNA error: %s\n", IDNA_strerror(_idna_errno));
}

int resolve_name (const char *name)
{
  struct hostent *he;
  char   host [100];
  size_t len;

  _strlcpy (host, name, sizeof(host)-1);
  len = sizeof (host);
  if (!IDNA_convert_to_ACE(host, &len))
  {
    print_last_error();
    return (-1);
  }

  he = gethostbyname (host);
  if (he)
       printf ("%s\n", inet_ntoa(*(struct in_addr*)he->h_addr));
  else printf ("failed (h_errno %d)\n", h_errno);
  return (0);
}

int reverse_resolve (struct in_addr addr)
{
  struct hostent *he = gethostbyaddr ((char*)&addr, sizeof(addr), AF_INET);
  char   host [100];
  size_t len;

  if (!he)
  {
    printf ("failed (code %d)\n", h_errno);
    return (-1);
  }

  _strlcpy (host,  he->h_name, sizeof(host)-1);
  printf ("raw ACE: \"%s\"\n", host);
  len = strlen (host);
  if (!IDNA_convert_from_ACE(host, &len))
  {
    print_last_error();
    return (-1);
  }
  printf (" -> \"%.*s\"", (int)len, host);
  return (0);
}

void sock_init (void)
{
  WSADATA wsa;
  WORD    ver = MAKEWORD(1,1);

  if (WSAStartup(ver, &wsa) != 0 || wsa.wVersion < ver)
  {
    printf ("Winsock init failed; code %s\n", win_strerror(GetLastError()));
    exit (-1);
  }
}

static int do_test (WORD cp, const char *host)
{
  struct in_addr addr;

  if (!IDNA_init(cp,g_cfg.idna_winidn))
  {
    printf ("%s\n", IDNA_strerror(_idna_errno));
    return (-1);
  }

  printf ("Resolving `%s'...", host);
  fflush (stdout);

  /* If 'host' is an IP-address, try to reverse resolve the address. Unfortunately
   * I've not found any ACE encoded hostname with a PTR record, so this may not
   * work.
   */
  addr.s_addr = inet_addr (host);
  if (addr.s_addr != INADDR_NONE)
     return reverse_resolve (addr);
  return resolve_name (host);
}

int main (int argc, char **argv)
{
  WORD cp = 0;
  int  ch, rc;

  while ((ch = getopt(argc, argv, "c:d" W_GETOPT "h?")) != EOF)
     switch (ch)
     {
       case 'c':
            cp = atoi (optarg);
            if ((int)cp < 0)
            {
              printf ("Illegal codepage '%s'\n", optarg);
              return (-1);
            }
            if (cp == 0)
            {
              cp = IDNA_GetCodePage();
              printf ("'-c0' maps to code-page %u.\n", cp);
            }
            break;
       case 'd':
            g_cfg.trace_level++;
            break;
       case 'w':
            g_cfg.idna_winidn = 1;
            break;
       case '?':
       case 'h':
       default:
            usage (argv[0]);
            break;
  }

  argc -= optind;
  argv += optind;
  if (!*argv)
     usage (argv[0]);

  sock_init();
  common_init();
  g_cfg.trace_stream = stdout;
  g_cfg.show_caller = TRUE;
  InitializeCriticalSection (&crit_sect);

  rc = do_test (cp, argv[0]);

  common_exit();

  return (rc);
}
#endif  /* TEST_IDNA */
