#include <string.h>
#include <time.h>
#include <maxminddb.h>

static MMDB_s g_mmdb = { 0 };

#define MAX_wchar_COUNTRY_NAME  50

typedef wchar_t mmdb_wname [MAX_wchar_COUNTRY_NAME];

static void crtdbg_init (void);
static void crtdbg_exit (void);

static void utf8_to_wchar (const void *in_buf, size_t in_len, mmdb_wname out_buf)
{
  wchar_t wide [300];

  if (!MultiByteToWideChar(CP_UTF8, 0, in_buf, in_len, out_buf, MAX_wchar_COUNTRY_NAME))
       wcscpy (out_buf, L"?");
  else out_buf [in_len] = '\0';
}

static BOOL geoip_get_country_data (MMDB_entry_s *const entry,
                                    mmdb_wname    country_code,
                                    mmdb_wname    country_name)
{
  MMDB_entry_data_s data;

  country_code[0] = country_name[0] = L'\0';

  char *path[3] = { "country", "iso_code", NULL };

  if (MMDB_aget_value(entry, &data, (const char *const *const) path) == MMDB_SUCCESS)
  {
    if (data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
       utf8_to_wchar (data.utf8_string, data.data_size, country_code);
  }

  path[1] = "names";
  if (MMDB_aget_value(entry, &data, (const char *const *const) path) == MMDB_SUCCESS)
  {
    if (data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
       utf8_to_wchar (data.utf8_string, data.data_size, country_name);
  }

  if (country_code[0] && country_name[0])
     return (TRUE);
  return (FALSE);
}

static BOOL geoip_get_continent_data (MMDB_entry_s *const entry,
                                      mmdb_wname    continent_code,
                                      mmdb_wname    continent_name)
{
  MMDB_entry_data_s data;
  char *path[4] = { NULL, NULL,  NULL, NULL };

  continent_code[0] = continent_name[0] = L'\0';

  path[0] = "continent";
  path[1] = "code";
  if (MMDB_aget_value(entry, &data, (const char *const *const) path) == MMDB_SUCCESS)
  {
    if (data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
       utf8_to_wchar (data.utf8_string, data.data_size, continent_code);
  }

  path [0] = "country";
  path [1] = "names";
  path [2] = "en";
  if (MMDB_aget_value(entry, &data, (const char *const *const) path) == MMDB_SUCCESS)
  {
    if (data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
       utf8_to_wchar (data.utf8_string, data.data_size, continent_name);
  }
  if (continent_code[0] && continent_name[0])
     return (TRUE);
  return (FALSE);
}

static BOOL geoip_get_asn_data (MMDB_entry_s *const entry,
                                uint16_t     *asn_number,
                                mmdb_wname    asn_name)
{
  MMDB_entry_data_s data;
  char *path[2] = { NULL, NULL };

  *asn_number = 0;
  asn_name[0] = L'\0';

  path[0] = "autonomous_system_organization";
  if (MMDB_aget_value(entry, &data, (const char *const *const) path) == MMDB_SUCCESS)
  {
    if (data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
       utf8_to_wchar (data.utf8_string, data.data_size, asn_name);
  }

  path[0] = "autonomous_system_number";
  if (MMDB_aget_value(entry, &data, (const char *const *const) path) == MMDB_SUCCESS && data.has_data)
     *asn_number = data.uint16;

  return (*asn_number || asn_name[0]);
}

static BOOL lookup_ipv4_address (const char *ip_address, BOOL get_asn)
{
  int                  rc = 0;
  int                  gai_error;
  mmdb_wname           country_code,   country_name;
  mmdb_wname           continent_code, continent_name;
  mmdb_wname           asn_name;
  uint16_t             asn_number, mask;
  MMDB_lookup_result_s result;

  memset (&result, 0, sizeof(result));
  result = MMDB_lookup_string (&g_mmdb, ip_address, &gai_error, &rc);
  if (!result.found_entry || rc)
  {
    printf ("Info on %s failed: %d/%s, gai_error: %d.\n",
            ip_address, rc, MMDB_strerror(rc), gai_error);
    return (FALSE);
  }

  mask = result.netmask;
  if (g_mmdb.metadata.ip_version == 6)
     mask -= 96;

  printf ("Info for IPv4 address %s/%d:\n", ip_address, mask);

  if (geoip_get_country_data (&result.entry, country_code, country_name))
       wprintf (L"  country_code:   %s, country_name:   %s\n", country_code, country_name);
  else wprintf (L"  country_code:   %s, country_name:   %s\n", L"<none>", L"<none>");

  if (geoip_get_continent_data (&result.entry, continent_code, continent_name))
       wprintf (L"  continent_code: %s, continent_name: %s\n", continent_code, continent_name);
  else wprintf (L"  continent_code: %s, continent_name: %s\n", L"<none>", L"<none>");

  if (get_asn)
  {
    if (geoip_get_asn_data (&result.entry, &asn_number, asn_name))
         wprintf (L"  ASN%-5u        %s\n", asn_number, asn_name);
    else wprintf (L"  ASN%-5c        %s\n", '?', L"<none>");
  }
  puts ("");
  return (TRUE);
}

static BOOL dump_metadata (const MMDB_metadata_s *meta)
{
  const  MMDB_description_s *descr;
  time_t t;
  int    i;
  uint32_t tree_section_size;

  puts ("Metadata:");
  printf ("  version:       %u.%u.\n", meta->binary_format_major_version, meta->binary_format_minor_version);
  printf ("  node_count:    %u.\n", meta->node_count);
  printf ("  record_size:   %u.\n", meta->record_size);
  printf ("  ip_version:    %u.\n", meta->ip_version);
  printf ("  database_type: %s.\n", meta->database_type);
  t = (time_t) meta->build_epoch;
  printf ("  build_epoch:   %.24s\n", ctime(&t));

  tree_section_size = (2 * meta->record_size) / 8;
  tree_section_size *= meta->node_count;
  printf ("  section-size:  %u\n", tree_section_size);

  printf ("  languages:\n");
  for (i = 0; i < meta->languages.count; i++)
     printf ("    %d: '%s'\n", i, meta->languages.names[i]);

  printf ("  descriptions:\n");
  for (i = 0; i < meta->description.count; i++)
  {
    descr = meta->description.descriptions [i];
    printf ("    %d: lang: '%s', description: '%s'\n", i, descr->language, descr->description);
  }
  puts ("");
  return (meta->binary_format_major_version == 2);
}

int main (int argc, char **argv)
{
  WSADATA     wsa;
  int         rc;
  const char *db_file = "test.mmdb";

  crtdbg_init();
  WSAStartup (MAKEWORD(1, 1), &wsa);

  if (argc >= 2)
     db_file = argv[1];

  rc = MMDB_open (db_file, MMDB_MODE_MMAP, &g_mmdb);
  if (rc != MMDB_SUCCESS)
  {
    printf ("MMDB_open (\"%s\") failed; %d/%s.\n", db_file, rc, MMDB_strerror(rc));
    WSACleanup();
    rc = 2;
  }
  else if (!dump_metadata(&g_mmdb.metadata))
  {
    printf ("Unexpected major-version: %d.\n", g_mmdb.metadata.binary_format_major_version);
    rc = 1;
  }
  else
  {
    lookup_ipv4_address ("1.1.1.1", TRUE);
    lookup_ipv4_address ("2.2.2.2", TRUE);
    lookup_ipv4_address ("4.4.4.4", TRUE);
    lookup_ipv4_address ("8.8.8.8", TRUE);
    rc = 0;
  }

  MMDB_close (&g_mmdb);
  WSACleanup();
  crtdbg_exit();
  return (rc);
}

#if defined(_MSC_VER) && defined(_DEBUG)
  static _CrtMemState last_state;

  static void crtdbg_init (void)
  {
    _CrtSetReportFile (_CRT_WARN, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode (_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetDbgFlag (_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) |
                    _CRTDBG_LEAK_CHECK_DF | _CRTDBG_DELAY_FREE_MEM_DF | _CRTDBG_ALLOC_MEM_DF);
    _CrtMemCheckpoint (&last_state);
  }
  static void crtdbg_exit (void)
  {
    _CrtMemState new_state, diff_state;

    _CrtMemCheckpoint (&new_state);
    if (_CrtMemDifference(&diff_state, &last_state, &new_state))
    {
      _CrtMemDumpAllObjectsSince (&last_state);
      _CrtMemDumpStatistics (&last_state);
      _CrtCheckMemory();
      _CrtDumpMemoryLeaks();
    }
  }

#else
  static void crtdbg_init (void)
  {
  }
  static void crtdbg_exit (void)
  {
  }
#endif

