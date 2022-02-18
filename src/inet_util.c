/**\file    inet_util.c
 * \ingroup inet_util
 *
 * \brief
 *  Functions for downloading files via `WinInet.dll` or `WinHttp.dll`
 *  and checking of address types.
 *
 * inet_util.c - Part of Wsock-Trace.
 */
#include "config.h"

#include <windows.h>
#include <limits.h>
#include <errno.h>
#include <wininet.h>

/*
 * Hacks to be able to include <winhttp.h> below.
 */
#define HTTP_VERSION_INFO    winhttp_HTTP_VERSION_INFO
#define LPHTTP_VERSION_INFO  winhttp_LPHTTP_VERSION_INFO

#define INTERNET_SCHEME      winhttp_INTERNET_SCHEME
#define LPINTERNET_SCHEME    winhttp_LPINTERNET_SCHEME

#define URL_COMPONENTS       winhttp_URL_COMPONENTS
#define LPURL_COMPONENTS     winhttp_LPURL_COMPONENTS

#define URL_COMPONENTSW      winhttp_URL_COMPONENTSW
#define LPURL_COMPONENTSW    winhttp_LPURL_COMPONENTSW

#undef BOOLAPI
#undef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#undef SECURITY_FLAG_IGNORE_CERT_CN_INVALID

#include <winhttp.h>

#include "common.h"
#include "init.h"
#include "in_addr.h"
#include "inet_util.h"

#define USER_AGENT_A    "Wsock-trace"
#define USER_AGENT_W   L"Wsock-trace"

#ifndef FILE_BUF_SIZE
#define FILE_BUF_SIZE  (10*1024)
#endif

#ifndef MAX_URL_SIZE
#define MAX_URL_SIZE   (sizeof("https://") + MAX_HOST_LEN + MAX_PATH)
#endif

#ifndef IN4_CLASSD
#define IN4_CLASSD(i)  (((LONG)(i) & 0x000000F0) == 0x000000E0)
#endif

/**
 * \def DEF_FUNC
 *
 * Handy macro to both define and declare the function-pointer for
 * `WinInet.dll` and `WinHttp.dll` functions.
 */
#define DEF_FUNC(ret, f, args)  typedef ret (WINAPI *func_##f) args; \
                                static func_##f p_##f = NULL

/**
 * Download a single file using the WinInet API.
 * Load `WinInet.dll` dynamically.
 */
DEF_FUNC (HINTERNET, InternetOpenA, (const char *user_agent,
                                     DWORD       access_type,
                                     const char *proxy_name,
                                     const char *proxy_bypass,
                                     DWORD       flags));

DEF_FUNC (HINTERNET, InternetOpenUrlA, (HINTERNET   hnd,
                                        const char *url,
                                        const char *headers,
                                        DWORD       headers_len,
                                        DWORD       flags,
                                        DWORD_PTR   context));

DEF_FUNC (BOOL, InternetGetLastResponseInfoA, (DWORD *err_code,
                                               char  *err_buff,
                                               DWORD *err_buff_len));

DEF_FUNC (BOOL, InternetReadFile, (HINTERNET hnd,
                                   void     *buffer,
                                   DWORD     num_bytes_to_read,
                                   DWORD    *num_bytes_read));

DEF_FUNC (BOOL, InternetReadFileExA, (HINTERNET          hnd,
                                      INTERNET_BUFFERSA *buf_out,
                                      DWORD              flags,
                                      DWORD_PTR          context));

DEF_FUNC (BOOL, InternetCloseHandle, (HINTERNET handle));

/*
 * Just for reference:
 *   typedef void (__stdcall *INTERNET_STATUS_CALLBACK) (HINTERNET hnd,
 *                                                       DWORD_PTR context,
 *                                                       DWORD     status,
 *                                                       void     *status_info,
 *                                                       DWORD     status_info_len);
 */
DEF_FUNC (INTERNET_STATUS_CALLBACK, InternetSetStatusCallback,
                                     (HINTERNET                hnd,
                                      INTERNET_STATUS_CALLBACK callback));

#define ADD_VALUE(func)  { 0, NULL, "wininet.dll", #func, (void**) &p_##func }

static struct LoadTable wininet_funcs[] = {
                        ADD_VALUE (InternetOpenA),
                        ADD_VALUE (InternetOpenUrlA),
                        ADD_VALUE (InternetGetLastResponseInfoA),
                        ADD_VALUE (InternetReadFile),
                        ADD_VALUE (InternetReadFileExA),
                        ADD_VALUE (InternetSetStatusCallback),
                        ADD_VALUE (InternetCloseHandle)
                      };

/***
 * A similar interface to WinHTTP. A comparision table: \n
 *   https://docs.microsoft.com/en-us/windows/desktop/winhttp/porting-wininet-applications-to-winhttp
 */
DEF_FUNC (HINTERNET, WinHttpOpen, (const wchar_t *agent,
                                   DWORD          access_type,
                                   const wchar_t *proxy,
                                   const wchar_t *proxy_bypass,
                                   DWORD          flags));

DEF_FUNC (HINTERNET, WinHttpConnect, (HINTERNET      hnd,
                                      const wchar_t *server_name,
                                      WORD           server_port,
                                      DWORD          reserved));

DEF_FUNC (BOOL, WinHttpCrackUrl, (const wchar_t           *url,
                                  DWORD                    url_len,
                                  DWORD                    flags,
                                  winhttp_URL_COMPONENTSW *url_comp));

DEF_FUNC (HINTERNET, WinHttpOpenRequest, (HINTERNET      hnd,
                                          const wchar_t  *verb,
                                          const wchar_t  *object_name,
                                          const wchar_t  *version,
                                          const wchar_t  *referrer,
                                          const wchar_t **ppwszAcceptTypes,
                                          DWORD           flags));

DEF_FUNC (BOOL, WinHttpSendRequest, (HINTERNET      hnd,
                                     const wchar_t *headers,
                                     DWORD          headers_len,
                                     void          *optional,
                                     DWORD          optional_len,
                                     DWORD          total_len,
                                     DWORD_PTR      context));

DEF_FUNC (BOOL, WinHttpQueryDataAvailable, (HINTERNET hnd,
                                            DWORD    *bytes_available));

DEF_FUNC (BOOL, WinHttpQueryHeaders, (HINTERNET hnd,
                                      DWORD     Info_level,
                                      wchar_t   *name,
                                      void      *buffer,
                                      DWORD     *buffer_len,
                                      DWORD     *index));

DEF_FUNC (BOOL, WinHttpReceiveResponse, (HINTERNET hnd,
                                         void     *reserved));

DEF_FUNC (BOOL, WinHttpReadData, (HINTERNET hnd,
                                  void     *buf,
                                  DWORD     bytes_to_read,
                                  DWORD    *bytes_read));

/** Luckily a `WINHTTP_STATUS_CALLBACK` is the same as a `INTERNET_STATUS_CALLBACK`.
 */
DEF_FUNC (INTERNET_STATUS_CALLBACK, WinHttpSetStatusCallback,
                                     (HINTERNET                hnd,
                                      INTERNET_STATUS_CALLBACK callback,
                                      DWORD                    notification_flags,
                                      DWORD_PTR                reserved));

DEF_FUNC (BOOL, WinHttpSetOption, (HINTERNET hnd,
                                   DWORD     option,
                                   void     *buf,
                                   DWORD     buf_len));

DEF_FUNC (BOOL, WinHttpCloseHandle, (HINTERNET hnd));

#undef  ADD_VALUE
#define ADD_VALUE(func)  { 0, NULL, "winhttp.dll", #func, (void**) &p_##func }

static struct LoadTable winhttp_funcs[] = {
                        ADD_VALUE (WinHttpOpen),
                        ADD_VALUE (WinHttpConnect),
                        ADD_VALUE (WinHttpCrackUrl),
                        ADD_VALUE (WinHttpOpenRequest),
                        ADD_VALUE (WinHttpSendRequest),
                        ADD_VALUE (WinHttpQueryDataAvailable),
                        ADD_VALUE (WinHttpQueryHeaders),
                        ADD_VALUE (WinHttpReadData),
                        ADD_VALUE (WinHttpReceiveResponse),
                        ADD_VALUE (WinHttpSetStatusCallback),
                        ADD_VALUE (WinHttpSetOption),
                        ADD_VALUE (WinHttpCloseHandle)
                      };

/*
 * Missing in AppVeyor's SDK and possibly others.
 */
#ifndef ERROR_WINHTTP_UNHANDLED_SCRIPT_TYPE
#define ERROR_WINHTTP_UNHANDLED_SCRIPT_TYPE          (12000 + 176)
#endif

#ifndef ERROR_WINHTTP_SCRIPT_EXECUTION_ERROR
#define ERROR_WINHTTP_SCRIPT_EXECUTION_ERROR         (12000 + 177)
#endif

#ifndef ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED_PROXY
#define ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED_PROXY  (12000 + 187)
#endif

#ifndef ERROR_WINHTTP_SECURE_FAILURE_PROXY
#define ERROR_WINHTTP_SECURE_FAILURE_PROXY           (12000 + 188)
#endif

#undef  ADD_VALUE
#define ADD_VALUE(x)   { ERROR_WINHTTP_ ##x, "ERROR_WINHTTP_" #x }

static const struct search_list winhttp_errors[] = {
                    ADD_VALUE (OUT_OF_HANDLES),
                    ADD_VALUE (TIMEOUT),
                    ADD_VALUE (INTERNAL_ERROR),
                    ADD_VALUE (INVALID_URL),
                    ADD_VALUE (UNRECOGNIZED_SCHEME),
                    ADD_VALUE (NAME_NOT_RESOLVED),
                    ADD_VALUE (INVALID_OPTION),
                    ADD_VALUE (OPTION_NOT_SETTABLE),
                    ADD_VALUE (SHUTDOWN),
                    ADD_VALUE (LOGIN_FAILURE),
                    ADD_VALUE (OPERATION_CANCELLED),
                    ADD_VALUE (INCORRECT_HANDLE_TYPE),
                    ADD_VALUE (INCORRECT_HANDLE_STATE),
                    ADD_VALUE (CANNOT_CONNECT),
                    ADD_VALUE (CONNECTION_ERROR),
                    ADD_VALUE (RESEND_REQUEST),
                    ADD_VALUE (CLIENT_AUTH_CERT_NEEDED),
                    ADD_VALUE (CANNOT_CALL_BEFORE_OPEN),
                    ADD_VALUE (CANNOT_CALL_BEFORE_SEND),
                    ADD_VALUE (CANNOT_CALL_AFTER_SEND),
                    ADD_VALUE (CANNOT_CALL_AFTER_OPEN),
                    ADD_VALUE (HEADER_NOT_FOUND),
                    ADD_VALUE (INVALID_SERVER_RESPONSE),
                    ADD_VALUE (INVALID_HEADER),
                    ADD_VALUE (INVALID_QUERY_REQUEST),
                    ADD_VALUE (HEADER_ALREADY_EXISTS),
                    ADD_VALUE (REDIRECT_FAILED),
                    ADD_VALUE (AUTO_PROXY_SERVICE_ERROR),
                    ADD_VALUE (BAD_AUTO_PROXY_SCRIPT),
                    ADD_VALUE (UNABLE_TO_DOWNLOAD_SCRIPT),
                    ADD_VALUE (UNHANDLED_SCRIPT_TYPE),
                    ADD_VALUE (SCRIPT_EXECUTION_ERROR),
                    ADD_VALUE (NOT_INITIALIZED),
                    ADD_VALUE (SECURE_FAILURE),
                    ADD_VALUE (SECURE_CERT_DATE_INVALID),
                    ADD_VALUE (SECURE_CERT_CN_INVALID),
                    ADD_VALUE (SECURE_INVALID_CA),
                    ADD_VALUE (SECURE_CERT_REV_FAILED),
                    ADD_VALUE (SECURE_CHANNEL_ERROR),
                    ADD_VALUE (SECURE_INVALID_CERT),
                    ADD_VALUE (SECURE_CERT_REVOKED),
                    ADD_VALUE (SECURE_CERT_WRONG_USAGE),
                    ADD_VALUE (AUTODETECTION_FAILED),
                    ADD_VALUE (HEADER_COUNT_EXCEEDED),
                    ADD_VALUE (HEADER_SIZE_OVERFLOW),
                    ADD_VALUE (CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW),
                    ADD_VALUE (RESPONSE_DRAIN_OVERFLOW),
                    ADD_VALUE (CLIENT_CERT_NO_PRIVATE_KEY),
                    ADD_VALUE (CLIENT_CERT_NO_ACCESS_PRIVATE_KEY),
                    ADD_VALUE (CLIENT_AUTH_CERT_NEEDED_PROXY),
                    ADD_VALUE (SECURE_FAILURE_PROXY)
                  };
/**
 * Return error-string for `err` from a `WinHttp.dll` function.
 */
static const char *winhttp_strerror (DWORD err)
{
  if (err > WINHTTP_ERROR_BASE && err <= WINHTTP_ERROR_LAST)
     return list_lookup_name (err, winhttp_errors, DIM(winhttp_errors));
  return win_strerror (err);
}

/**
 * Return error-string for `err` from `WinInet.dll`.
 *
 * Try to get a more detailed error-code and text from
 * the server response using `InternetGetLastResponseInfoA()`.
 */
static const char *wininet_strerror (DWORD err)
{
  HMODULE mod = GetModuleHandle ("wininet.dll");
  char    buf[512];

  if (mod && mod != INVALID_HANDLE_VALUE &&
      FormatMessageA (FORMAT_MESSAGE_FROM_HMODULE,
                      mod, err, MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
                      buf, sizeof(buf), NULL))
  {
    static char err_buf[512];
    char   wininet_err_buf[200];
    char  *p;
    DWORD  wininet_err = 0;
    DWORD  wininet_err_len = sizeof(wininet_err_buf)-1;

    str_rip (buf);
    p = strrchr (buf, '.');
    if (p && p[1] == '\0')
       *p = '\0';

    p = err_buf;
    p += snprintf (err_buf, sizeof(err_buf), "%lu: %s", (u_long)err, buf);

    if ((*p_InternetGetLastResponseInfoA) (&wininet_err, wininet_err_buf, &wininet_err_len) &&
        wininet_err > INTERNET_ERROR_BASE && wininet_err <= INTERNET_ERROR_LAST)
    {
      snprintf (p, (size_t)(p-err_buf), " (%lu/%s)", (u_long)wininet_err, wininet_err_buf);
      p = strrchr (p, '.');
      if (p && p[1] == '\0')
         *p = '\0';
    }
    return (err_buf);
  }
  return win_strerror (err);
}

/**
 * A simple `q` / ESC-handler to force the below async-loop to quit.
 *
 * I tried setting up a ^C|^Break handler using `SetConsoleCtrlHandler()`,
 * but that doesn't seems to work in a DLL (?)
 */
static BOOL check_quit (void)
{
  if (_kbhit())
  {
    int ch = _getch();

    if (ch == 'q' || ch == 27) /* `q` or ESC */
       return (1);
  }
  return (0);
}

#undef  ADD_VALUE
#define ADD_VALUE(x)   { INTERNET_STATUS_ ##x, "INTERNET_STATUS_" #x }

static const struct search_list internet_status_list[] = {
                    ADD_VALUE (RESOLVING_NAME),
                    ADD_VALUE (NAME_RESOLVED),
                    ADD_VALUE (CONNECTING_TO_SERVER),
                    ADD_VALUE (CONNECTED_TO_SERVER),
                    ADD_VALUE (SENDING_REQUEST),
                    ADD_VALUE (REQUEST_SENT),
                    ADD_VALUE (RECEIVING_RESPONSE),
                    ADD_VALUE (RESPONSE_RECEIVED),
                    ADD_VALUE (CTL_RESPONSE_RECEIVED),
                    ADD_VALUE (PREFETCH),
                    ADD_VALUE (CLOSING_CONNECTION),
                    ADD_VALUE (CONNECTION_CLOSED),
                    ADD_VALUE (HANDLE_CREATED),
                    ADD_VALUE (HANDLE_CLOSING),
                    ADD_VALUE (DETECTING_PROXY),
                    ADD_VALUE (REQUEST_COMPLETE),
                    ADD_VALUE (REDIRECT),
                    ADD_VALUE (INTERMEDIATE_RESPONSE),
                    ADD_VALUE (USER_INPUT_REQUIRED),
                    ADD_VALUE (STATE_CHANGE),
                    ADD_VALUE (COOKIE_SENT),
                    ADD_VALUE (COOKIE_RECEIVED),
                    ADD_VALUE (PRIVACY_IMPACTED),
                    ADD_VALUE (P3P_HEADER),
                    ADD_VALUE (P3P_POLICYREF),
                    ADD_VALUE (COOKIE_HISTORY)
                  };

struct wininet_context {
       HINTERNET         h1;             /**< Handle from `(*p_InternetOpenA)()` */
       HINTERNET         h2;             /**< Handle from `(*p_InternetOpenUrlA)()` */
       volatile BOOL     done;
       BOOL              threaded_mode;
       BOOL              async_mode;
       BOOL              async_flag;
       INTERNET_BUFFERSA inet_buf;
     };

struct winhttp_context {
       HINTERNET               h1;        /**< Handle from `(*p_WinHttpOpen)()` */
       HINTERNET               h2;        /**< Handle from `(*p_WinHttpConnect)()` */
       HINTERNET               h3;        /**< Handle from `(*p_WinHttpOpenRequest)()` */
       winhttp_URL_COMPONENTSW url_comp;
     };

struct download_context {
       const char       *url;
       const char       *file_name;
       char              file_buf [FILE_BUF_SIZE];
       FILE             *fil;
       DWORD             bytes_read;     /**< Last `(*p_WinHttpReadData)()` or `(*p_WinHttpReadData)()` read-count */
       DWORD             bytes_written;  /**< Accumulated bytes written to `fil` */
       int               error;
       union {
         struct wininet_context wininet;
         struct winhttp_context winhttp;
       } u;
    };

/**
 * The WinInet callback called from `download_async_loop()`.
 */
static void CALLBACK download_callback (HINTERNET hnd,
                                        DWORD_PTR _ctx,
                                        DWORD     status,
                                        void     *status_info,
                                        DWORD     status_info_len)
{
  struct download_context       *context = (struct download_context*) _ctx;
  struct wininet_context        *ctx = &context->u.wininet;
  const INTERNET_ASYNC_RESULT   *ar  = (const INTERNET_ASYNC_RESULT*) status_info;
  const INTERNET_CONNECTED_INFO *ci  = (const INTERNET_CONNECTED_INFO*) status_info;
  const char                    *status_name = list_lookup_name (status, internet_status_list, DIM(internet_status_list));

  TRACE (1, "%sstatus: %s (%lu).\n"
            "                               hnd: 0x%p, ctx->h1: 0x%p, ctx->h2: 0x%p.\n",
         get_timestamp(), status_name, (unsigned long)status, hnd, ctx->h1, ctx->h2);

  if (ctx->h2 && hnd != ctx->h2)
     TRACE (1, "Wrong handle\n");

  if (status == INTERNET_STATUS_HANDLE_CREATED)
  {
    HINTERNET h2 = (HINTERNET) ar->dwResult;

    TRACE (1, "INTERNET_STATUS_HANDLE_CREATED: h2: 0x%p, file_name: %s\n", h2, context->file_name);
    ctx->h2 = h2;
  }
  else if (status == INTERNET_STATUS_CONNECTED_TO_SERVER)
  {
    TRACE (1, "INTERNET_STATUS_CONNECTED_TO_SERVER: dwConnectedState: 0x%08lX, dwFlags: 0x%08lX\n",
           (unsigned long)ci->dwConnectedState, (unsigned long)ci->dwFlags);
  }
  else if (status == INTERNET_STATUS_STATE_CHANGE)
  {
    TRACE (1, "INTERNET_STATUS_STATE_CHANGE: dwConnectedState: %lu, dwFlags: %lu\n",
           (unsigned long)ci->dwConnectedState, (unsigned long)ci->dwFlags);
  }
  else if (status == INTERNET_STATUS_REQUEST_COMPLETE)
  {
    TRACE (1, "INTERNET_STATUS_REQUEST_COMPLETE: dwResult: 0x%" ADDR_FMT ", dwError: %s\n",
           ADDR_CAST(ar->dwResult), wininet_strerror(ar->dwError));

    if (ar->dwResult > 0)
    {
      BOOL rc;
      do
      {
        rc = (*p_InternetReadFileExA) (ctx->h2, &ctx->inet_buf, WININET_API_FLAG_ASYNC, _ctx);
        context->bytes_read     = ctx->inet_buf.dwBufferLength;
        context->bytes_written += (DWORD) fwrite (context->file_buf, 1, (size_t)context->bytes_read, context->fil);
        ctx->inet_buf.dwBufferLength = sizeof(context->file_buf);
        TRACE (2, "  InternetReadFileExA(): rc: %d, %lu bytes\n", rc, (unsigned long)context->bytes_read);
      }
      while (rc && context->bytes_read > 0);

      if (GetLastError() != ERROR_IO_PENDING)
      {
        (*p_InternetCloseHandle) (hnd);
        (*p_InternetCloseHandle) (ctx->h2);
        ctx->h1 = ctx->h2 = NULL;
        ctx->done = TRUE;
      }
    }
    else
    {
      (*p_InternetCloseHandle) (hnd);
      (*p_InternetCloseHandle) (ctx->h2);
      ctx->h1 = ctx->h2 = NULL;
    }
  }
  ARGSUSED (status_info_len);
}

static BOOL download_init (struct download_context *context)
{
  struct wininet_context *ctx = &context->u.wininet;
  DWORD       access_type  = INTERNET_OPEN_TYPE_DIRECT;
  const char *proxy_name   = NULL;
  const char *proxy_bypass = NULL;

  if (g_cfg.GEOIP.proxy && g_cfg.GEOIP.proxy[0])
  {
    proxy_name   = g_cfg.GEOIP.proxy;
    proxy_bypass = "<local>";
    access_type  = INTERNET_OPEN_TYPE_PROXY;
  }

  TRACE (1, "Calling InternetOpenA(): proxy: %s, URL: %s.\n",
         proxy_name ? proxy_name : "<none>", context->url);

  ctx->h1 = (*p_InternetOpenA) (USER_AGENT_A, access_type, proxy_name, proxy_bypass, ctx->async_flag);
  if (!ctx->h1)
  {
    DWORD error = GetLastError();

    TRACE (0, "InternetOpenA() failed: %s.\n", wininet_strerror(error));
    return (FALSE);
  }

  if (ctx->async_mode)
  {
    TRACE (1, "Calling InternetSetStatusCallback(), ctx->h1: %p\n", ctx->h1);

    (*p_InternetSetStatusCallback) (ctx->h1, download_callback);
    ctx->h2 = (*p_InternetOpenUrlA) (ctx->h1, context->url, NULL, 0,
                                     INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_CACHE_WRITE,
                                     (DWORD_PTR) context);
  }
  else
    ctx->h2 = (*p_InternetOpenUrlA) (ctx->h1, context->url, NULL, 0,
                                     INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_CACHE_WRITE,
                                     INTERNET_NO_CALLBACK);

  TRACE (1, "Calling InternetOpenUrlA(): h2: %p, threaded_mode: %d, async_mode: %d\n",
         ctx->h2, ctx->threaded_mode, ctx->async_mode);

  if (!ctx->h2)
  {
    DWORD error = GetLastError();

    if (error != ERROR_IO_PENDING)  /* ctx->async_mode == TRUE */
    {
      TRACE (1, "InternetOpenA() failed: %s.\n", wininet_strerror(error));
      return (FALSE);
    }
  }
  return (TRUE);
}

static DWORD download_exit (struct download_context *context)
{
  struct wininet_context *ctx = &context->u.wininet;

  TRACE (1, "download_exit (%s) -> bytes_written: %lu\n",
         context->file_name, DWORD_CAST(context->bytes_written));

  if (context->fil)
     fclose (context->fil);

  if (ctx->h2)
    (*p_InternetCloseHandle) (ctx->h2);

  if (ctx->h1)
  {
    if (ctx->async_mode)
    {
      TRACE (1, "InternetSetStatusCallback (context.h1, NULL)\n");
      (*p_InternetSetStatusCallback) (ctx->h1, NULL);
    }
    (*p_InternetCloseHandle) (ctx->h1);
  }
  return (0);
}

/**
 * Download a file using `WinInet.dll` in synchronous mode.
 */
static DWORD WINAPI download_sync_loop (struct download_context *context)
{
  struct wininet_context *ctx = &context->u.wininet;

  if (ctx->threaded_mode)
     TRACE (1, "Threaded: entering download_sync_loop()");

  if (!download_init(context))
     return (0);

  while (!ctx->done)
  {
    if (!(*p_InternetReadFile)(ctx->h2, context->file_buf, sizeof(context->file_buf), &context->bytes_read))
       break;

    TRACE (2, "InternetReadFile() read %lu bytes.\n", (unsigned long)context->bytes_read);
    if (context->bytes_read == 0)
       break;
    context->bytes_written += (DWORD) fwrite (context->file_buf, 1, (size_t)context->bytes_read, context->fil);
  }
  return download_exit (context);
}

/**
 * Download a file using `WinInet.dll` in asynchronous mode.
 */
static DWORD WINAPI download_async_loop (struct download_context *context)
{
  struct wininet_context *ctx = &context->u.wininet;

  if (ctx->threaded_mode)
     TRACE (1, "Threaded: entering download_async_loop().");

  if (!download_init(context))
     return (0);

  while (!ctx->done)
  {
    if (check_quit())
    {
      TRACE (1, "Quit'.\n");
      ctx->done = TRUE;
      break;
    }
    TRACE (1, "%sLooping waiting for 'ctx->done'.\n", get_timestamp());
    if (SleepEx(200, TRUE) == WAIT_IO_COMPLETION)
       TRACE (1, "WAIT_IO_COMPLETION.\n");
  }
  return download_exit (context);
}

/**
 * Download a file using `WinInet.dll` in synchronous or asynchronous mode.
 */
static void download_threaded (struct download_context *context)
{
  struct wininet_context *ctx = &context->u.wininet;
  BOOL   t_timedout = FALSE;
  DWORD  t_id;
  HANDLE t_hnd;

  if (ctx->async_mode)
       t_hnd = CreateThread (NULL, 0, (PTHREAD_START_ROUTINE)download_async_loop, context, 0, &t_id);
  else t_hnd = CreateThread (NULL, 0, (PTHREAD_START_ROUTINE)download_sync_loop, context, 0, &t_id);

  if (t_hnd != INVALID_HANDLE_VALUE)
  {
    if (WaitForSingleObject(t_hnd, 3000) != WAIT_OBJECT_0)
    {
      TerminateThread (t_hnd, 1);
      t_timedout = TRUE;
    }
    CloseHandle (t_hnd);
  }
  TRACE (1, "%s() finished, t_hnd: %p, t_tid: %lu, t_timedout: %d.\n",
         __FUNCTION__, t_hnd, (unsigned long)t_id, t_timedout);
}

/**
 * Download a file using `WinHttp.dll`.
 */
static void download_winhttp (struct download_context *context)
{
  struct winhttp_context *ctx = &context->u.winhttp;

  wchar_t url_wide [MAX_URL_SIZE];
  wchar_t host [MAX_HOST_LEN];
  wchar_t path [MAX_PATH];
  BOOL    success = FALSE;

  winhttp_URL_COMPONENTSW *url_comp = &ctx->url_comp;

  if (!MultiByteToWideChar(CP_ACP, 0, context->url, -1, url_wide, DIM(url_wide)))
  {
    TRACE (1, "Failed to convert context->url '%s' to 'wchar_t'.\n", context->url);
    return;
  }

  TRACE (3, "url_wide '%S'.\n", url_wide);

  if (!(*p_WinHttpCrackUrl)(url_wide, 0, 0, url_comp))
  {
    TRACE (1, "WinHttpCrackUrl() failed: %s.\n", win_strerror(GetLastError()));
    return;
  }

  wcsncpy (host, url_comp->lpszHostName, DIM(host)-1);
  host [url_comp->dwHostNameLength] = L'\0';

  wcsncpy (path, url_comp->lpszUrlPath, DIM(path)-1);
  path [url_comp->dwUrlPathLength] = L'\0';

  TRACE (2, "host: '%" WCHAR_FMT "'.\n"
            "                  path: '%" WCHAR_FMT "'.\n", host, path);

  /* Obtain a session handle.
   */
  ctx->h1 = (*p_WinHttpOpen) (USER_AGENT_W,
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS, 0);
  TRACE (2, "WinHttpOpen(): context->h1: %p.\n", ctx->h1);

  if (ctx->h1)
  {
    ctx->h2 = (*p_WinHttpConnect) (ctx->h1, host, 80, 0);
    TRACE (2, "WinHttpConnect(): ctx->h2: %p.\n", ctx->h2);
  }

  /* Create an HTTP Request handle.
   */
  if (ctx->h2)
  {
    ctx->h3 = (*p_WinHttpOpenRequest) (ctx->h2, L"GET", path,
                                       NULL, NULL, NULL,
                                       /* This adds a "Pragma: no-cache" to the header */
                                       WINHTTP_FLAG_REFRESH);
    TRACE (2, "WinHttpOpenRequest(): ctx->h3: %p.\n", ctx->h3);
  }

  /* Send the request.
   */
  if (ctx->h3)
  {
    success = (*p_WinHttpSendRequest) (ctx->h3, NULL, 0, NULL, 0, 0, 0);
    TRACE (2, "WinHttpSendRequest(): success: %d.\n", success);
  }

  /* Receive the response(es).
   */
  if (success)
  {
    DWORD chunk_size = 0;
    int   chunk = 1;

    success = (*p_WinHttpReceiveResponse) (ctx->h3, NULL);
    TRACE (2, "WinHttpReceiveResponse(): success: %d.\n", success);

    do
    {
      /* Check for available HTTP data (ignore any HTTP headers).
       */
      if (!(*p_WinHttpQueryDataAvailable)(ctx->h3, &chunk_size))
      {
        TRACE (2, "WinHttpQueryDataAvailable(): %s.\n", win_strerror(GetLastError()));
        break;
      }
      if (chunk_size == 0)
      {
        TRACE (2, "No more data.\n");
        break;
      }

      chunk_size = min (chunk_size, sizeof(context->file_buf));

      /* Get the data and write to the 'context->fil'.
       */
      if (!(*p_WinHttpReadData)(ctx->h3, context->file_buf, chunk_size, &context->bytes_read))
         TRACE (1, "WinHttpReadData(): %s.\n", win_strerror(GetLastError()));
      else
      {
        context->bytes_written += (DWORD) fwrite (context->file_buf, 1, (size_t)context->bytes_read, context->fil);
        TRACE (2, "WinHttpReadData(), got chunk %d size %lu.\n", chunk++, (unsigned long)context->bytes_read);
      }
    }
    while (chunk_size > 0);
  }

  /* Report any errors.
   */
  if (!success)
     TRACE (1, "Error: %s.\n", winhttp_strerror(GetLastError()));

  if (ctx->h3)
     (*p_WinHttpCloseHandle) (ctx->h3);

  if (ctx->h2)
     (*p_WinHttpCloseHandle) (ctx->h2);

  if (ctx->h1)
     (*p_WinHttpCloseHandle) (ctx->h1);

  ctx->h1 = ctx->h2 = ctx->h3 = NULL;

  TRACE (1, "%s(): %s -> bytes_written: %lu\n",
         __FUNCTION__, context->file_name, DWORD_CAST(context->bytes_written));

  if (context->fil)
     fclose (context->fil);
}

/**
 * Download a file from url using dynamcally loaded functions
 * from `WinInet.dll` or `WinHttp.dll`.
 *
 * \param[in] file the file to write to.
 * \param[in] url  the URL to retrieve from.
 * \retval    The number of bytes written to `file`.
 *
 * \note It is not safe to call this from `DllMain()`.\n
 *       Ref: https://docs.microsoft.com/en-gb/windows/desktop/Dlls/dynamic-link-library-best-practices
 */
DWORD INET_util_download_file (const char *file, const char *url)
{
  static struct download_context context;
  struct LoadTable *funcs;
  const char       *tab_dll;
  int               tab_size;
  BOOL              use_threaded = FALSE;
  BOOL              use_async    = FALSE;

  if (ws_from_dll_main)
  {
    TRACE (1, "Not safe to enter here from 'DllMain()'.\n");
    return (0);
  }

  if (g_cfg.use_winhttp)
  {
    funcs    = winhttp_funcs;
    tab_size = DIM (winhttp_funcs);
    tab_dll  = "WinHttp.dll";
  }
  else
  {
    funcs    = wininet_funcs;
    tab_size = DIM (wininet_funcs);
    tab_dll  = "WinInet.dll";
  }

  if (load_dynamic_table(funcs, tab_size) != tab_size)
  {
    TRACE (1, "Failed to load the needed %s functions.\n", tab_dll);
    return (0);
  }

  memset (&context, '\0', sizeof(context));
  context.url       = url;
  context.file_name = file;
  context.fil       = fopen (context.file_name, "w+b");

  if (!context.fil)
     context.error = errno;

  else if (g_cfg.use_winhttp)
  {
    context.u.winhttp.url_comp.dwStructSize     = sizeof(context.u.winhttp.url_comp);
    context.u.winhttp.url_comp.dwSchemeLength   = (DWORD)-1;
    context.u.winhttp.url_comp.dwHostNameLength = (DWORD)-1;
    context.u.winhttp.url_comp.dwUrlPathLength  = (DWORD)-1;
  }
  else
  {
    context.u.wininet.inet_buf.dwStructSize   = sizeof(context.u.wininet.inet_buf);
    context.u.wininet.inet_buf.dwBufferLength = sizeof(context.file_buf);
    context.u.wininet.inet_buf.lpvBuffer      = context.file_buf;

    context.u.wininet.threaded_mode = use_threaded;
    context.u.wininet.async_mode    = use_async;
    context.u.wininet.async_flag    = use_async ? INTERNET_FLAG_ASYNC : 0;
    context.u.wininet.async_flag   |= INTERNET_FLAG_NO_COOKIES;         /* no automatic cookie handling */
  }

  if (context.fil)
  {
    if (g_cfg.use_winhttp)
         download_winhttp (&context);
    else if (use_threaded)
         download_threaded (&context);
    else if (use_async)
         download_async_loop (&context);
    else download_sync_loop (&context);
  }

  unload_dynamic_table (funcs, tab_size);
  return (context.bytes_written);
}

/**
 * Touch a file to current time.
 */
int INET_util_touch_file (const char *file)
{
  struct stat st;
  int    rc;

  stat (file, &st);
  TRACE (2, "touch_file: %s", ctime(&st.st_mtime));
  rc = _utime (file, NULL);
  stat (file, &st);
  TRACE (2, "         -> %s\n", ctime(&st.st_mtime));
  return (rc);
}

/*
 * IPv6-address classify functions:
 *
 * Fix for building with `gcc -O0` and the GCC `extern __inline__`
 * insanity.
 */
#if defined(__GNUC__) && defined(__NO_INLINE__)   /* -O0 */
  int IN6_IS_ADDR_UNSPECIFIED (const struct in6_addr *a)
  {
    return ((a->s6_words[0] == 0) && (a->s6_words[1] == 0) &&
            (a->s6_words[2] == 0) && (a->s6_words[3] == 0) &&
            (a->s6_words[4] == 0) && (a->s6_words[5] == 0) &&
            (a->s6_words[6] == 0) && (a->s6_words[7] == 0));
  }

  int IN6_IS_ADDR_LOOPBACK (const struct in6_addr *a)
  {
    return ((a->s6_words[0] == 0) && (a->s6_words[1] == 0) &&
            (a->s6_words[2] == 0) && (a->s6_words[3] == 0) &&
            (a->s6_words[4] == 0) && (a->s6_words[5] == 0) &&
            (a->s6_words[6] == 0) && (a->s6_words[7] == 0x0100));
  }

  int IN6_IS_ADDR_LINKLOCAL (const struct in6_addr *a)
  {
    return ((a->s6_bytes[0] == 0xFE) && ((a->s6_bytes[1] & 0xC0) == 0x80));
  }

  int IN6_IS_ADDR_SITELOCAL (const struct in6_addr *a)
  {
    return ((a->s6_bytes[0] == 0xFE) && ((a->s6_bytes[1] & 0xC0) == 0xC0));
  }

  int IN6_IS_ADDR_V4MAPPED (const struct in6_addr *a)
  {
    return ((a->s6_words[0] == 0) && (a->s6_words[1] == 0) &&
            (a->s6_words[2] == 0) && (a->s6_words[3] == 0) &&
            (a->s6_words[4] == 0) && (a->s6_words[5] == 0xFFFF));
  }

  int IN6_IS_ADDR_V4COMPAT (const struct in6_addr *a)
  {
    return ((a->s6_words[0] == 0) && (a->s6_words[1] == 0) &&
            (a->s6_words[2] == 0) && (a->s6_words[3] == 0) &&
            (a->s6_words[4] == 0) && (a->s6_words[5] == 0) &&
            !((a->s6_words[6] == 0) && (a->s6_addr[14] == 0) &&
             ((a->s6_addr[15] == 0) || (a->s6_addr[15] == 1))));
  }
#endif

/*
 * Modified from <mstcpip.h> since not all targets or SDKs contain these:
 */
int IN6_IS_ADDR_6TO4 (const struct in6_addr *a)
{
  return (a->s6_words[0] == 0x0220); /* == IN6ADDR_6TO4PREFIX_INIT swapped */
}

int IN6_IS_ADDR_ISATAP (const struct in6_addr *a)
{
  return ((a->s6_words[4] & 0xFFFD) == 0) && (a->s6_words[5] == 0xFE5E);
}

/*
 * Taken from:
 *   ettercap -- IP address management
 *
 *  Copyright (C) ALoR & NaGA
 *
 * ... and rewritten.
 *
 * return 1 if the `ip4` / `ip6` address is `0.0.0.0` or `0::`.
 */
int INET_util_addr_is_zero (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  if (ip4)
  {
    if (!memcmp(ip4, "\x00\x00\x00\x00", sizeof(*ip4)))
       return (1);
  }
  else if (ip6)
  {
    if (!memcmp(ip6, "\x00\x00\x00\x00\x00\x00\x00\x00"   /* IN6_IS_ADDR_UNSPECIFIED() */
                     "\x00\x00\x00\x00\x00\x00\x00\x00", sizeof(*ip6)))
       return (1);
  }
  return (0);
}

/**
 * returns 1 if the `ip4` / `ip6` address is a multicast address.
 * returns 0 if not
 */
int INET_util_addr_is_multicast (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  if (ip4)
  {
    if (IN4_CLASSD(ip4->s_addr))  /* 224.0.0.0/4, Global multicast */
       return (1);
  }
  else if (ip6)
  {
    if (ip6->s6_bytes[0] == 0xFF) /* ff00::/8, Global multicast */
       return (1);
  }
  return (0);
}

#define SET_REMARK(what) do {                 \
                           if (remark)        \
                              *remark = what; \
                         } while (0)

/**
 * Check if an IPv4 or IPv6 address is "special".
 * If it is return 1. And optionally return a remark describing why.
 */
int INET_util_addr_is_special (const struct in_addr *ip4, const struct in6_addr *ip6, const char **remark)
{
  if (remark)
     *remark = NULL;

  if (ip4)
  {
    /* 240.0.0.0/4, https://whois.arin.net/rest/net/NET-240-0-0-0-0
     */
    if (ip4->S_un.S_un_b.s_b1 >= 240)
    {
      if (ip4->S_un.S_un_b.s_b1 == 255)
           SET_REMARK ("Broadcast");
      else SET_REMARK ("Future use");
      return (1);
    }

    /* 169.254.0.0/16, https://whois.arin.net/rest/net/NET-169-254-0-0-1
     */
    if (ip4->S_un.S_un_b.s_b1 == 169 && ip4->S_un.S_un_b.s_b2 == 254)
    {
      SET_REMARK ("Link Local");
      return (1);
    }

    /* 100.64.0.0/10, https://whois.arin.net/rest/net/NET-100-64-0-0-1
     */
    if (ip4->S_un.S_un_b.s_b1 == 100 &&
        (ip4->S_un.S_un_b.s_b2 >= 64 && ip4->S_un.S_un_b.s_b2 <= 127))
    {
      SET_REMARK ("Shared Address Space");
      return (1);
    }
  }
  else if (ip6)
  {
    if (IN6_IS_ADDR_LOOPBACK(ip6))
    {
      SET_REMARK ("Loopback");
      return (1);
    }
    if (IN6_IS_ADDR_LINKLOCAL(ip6))
    {
      SET_REMARK ("Link Local");
      return (1);
    }
    if (IN6_IS_ADDR_SITELOCAL(ip6))
    {
      SET_REMARK ("Site Local");
      return (1);
    }
    if (IN6_IS_ADDR_V4COMPAT(ip6))
    {
      SET_REMARK ("IPv4 compatible");
      return (1);
    }
    if (IN6_IS_ADDR_V4MAPPED(ip6))
    {
      SET_REMARK ("IPv4 mapped");
      return (1);
    }
    if (IN6_IS_ADDR_6TO4(ip6))
    {
      SET_REMARK ("6to4");
      return (1);
    }
    if (IN6_IS_ADDR_ISATAP(ip6))
    {
      SET_REMARK ("ISATAP");
      return (1);
    }

    /**
     * Teredo in RFC 4380 is `2001:0::/32`: \n
     * http://www.ipuptime.net/Teredo.aspx
     */
    if (ip6->s6_bytes[0] == 0x20 &&
        ip6->s6_bytes[1] == 0x01 &&
        ip6->s6_bytes[2] == 0x00)
    {
      SET_REMARK ("Teredo");
      return (1);
    }

    /* Old WinXP Teredo prefix, 3FFE:831F::/32
     * https://technet.microsoft.com/en-us/library/bb457011.aspx
     */
    if (ip6->s6_bytes[0] == 0x3F && ip6->s6_bytes[1] == 0xFE &&
        ip6->s6_bytes[2] == 0x83 && ip6->s6_bytes[3] == 0x1F)
    {
      SET_REMARK ("Teredo old");
      return (1);
    }
  }
  return (0);
}

#undef SET_REMARK

/**
 * Returns 1 if the `ip4` / `ip6` address is a Global Unicast
 * returns 0 if not
 */
int INET_util_addr_is_global (const struct in_addr *ip4, const struct in6_addr *ip6)
{
   if (ip4)
   {
     /**
      * Global for IPv4 means not status "RESERVED" by IANA.
      * Ref: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
      */
     if (ip4->S_un.S_un_b.s_b1 != 0x0  &&                       /* not 0/8        */
         ip4->S_un.S_un_b.s_b1 != 0x7F &&                       /* not 127/8      */
         ip4->S_un.S_un_b.s_b1 != 0x0A &&                       /* not 10/8       */
         (swap16(ip4->S_un.S_un_w.s_w1) & 0xFFF0) != 0xAC10 &&  /* not 172.16/12  */
         swap16(ip4->S_un.S_un_w.s_w1) != 0xC0A8 &&             /* not 192.168/16 */
         !INET_util_addr_is_multicast(ip4, NULL))               /* not 224/3      */
        return (1);
   }
   else if (ip6)
   {
     /**
      * As IANA does not apply masks > 8-bit for Global Unicast block,
      * only the first 8-bit are significant for this test.
      *
      * According to:
      *   https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml
      *
      * all 2001 - 2C00 blocks are ALLOCATED. So use that.
      *
      * \todo But use `iana_find_by_ip6_address()` to verify this.
      */
#if 0
     if ((ip6->s6_bytes[0] & 0xE0) == 0x20)   /* FALSE for e.g. '2c00::' */
#else
     if (swap16(ip6->s6_words[0]) >= 0x2001 && swap16(ip6->s6_words[0]) <= 0x2C00)
#endif
     {
       /*
        * This may be extended in future as IANA assigns further ranges
        * to Global Unicast.
        */
       return (1);
     }
   }
   return (0);
}

/**
 * Return an IP-number as a string.
 */
const char *INET_util_get_ip_num (const struct in_addr *ip4, const struct in6_addr *ip6)
{
  static char buf [4*sizeof("65535")+1];
  const u_long *dword;

  if (ip4)
     return _ultoa (swap32(ip4->s_addr), buf, 10);
  if (ip6)
  {
    dword = (const u_long*) &ip6->s6_bytes[0];
    snprintf (buf, sizeof(buf), "%lu%lu%lu%lu",
              dword[0], dword[1], dword[2], dword[3]);
  }
  else
  {
    buf[0] = '?';
    buf[1] = '\0';
  }
  return (buf);
}

/**
 * Figure out the prefix length when given an IPv4 "low" and "high" address.
 */
int INET_util_network_len32 (DWORD hi, DWORD lo)
{
  DWORD m = (hi - lo);

  m = (m & 0x55555555) + ((m & 0xAAAAAAAA) >> 1);
  m = (m & 0x33333333) + ((m & 0xCCCCCCCC) >> 2);
  m = (m & 0x0F0F0F0F) + ((m & 0xF0F0F0F0) >> 4);
  m = (m & 0x00FF00FF) + ((m & 0xFF00FF00) >> 8);
  m = (m & 0x0000FFFF) + ((m & 0xFFFF0000) >> 16);
  return (int) m;
}

/**
 * Figure out the prefix length by checking the common `1`s in each
 * of the 16 BYTEs in IPv6-addresses `*a` and `*b`.
 *
 * Currently not used.
 */
int INET_util_network_len128 (const struct in6_addr *a, const struct in6_addr *b)
{
  int  i, j, bits = 0;
  BYTE v;

  for (i = IN6ADDRSZ-1; i >= 0; i--)
  {
    v = (a->s6_bytes[i] ^ b->s6_bytes[i]);
    for (j = 0; j < 8; j++, bits++)
        if ((v & (1 << j)) == 0)
           goto quit;
  }
quit:
  return (MAX_IPV6_CIDR_MASK - bits);  /* 128 - bits */
}

/**
 * The `bits` is the suffix from a CIDR notation: "prefix/suffix".
 * Taken from libnet.
 */
void INET_util_get_mask4 (struct in_addr *out, int bits)
{
  *(DWORD*)out = bits ? swap32 (~0 << (32 - bits)) : 0;
}

/**
 * Taken from libdnet's `addr_btom()` and modified: \n
 *   https://github.com/nmap/nmap/blob/master/libdnet-stripped/src/addr.c?L441#L441-L470
 */
void INET_util_get_mask6 (struct in6_addr *out, int bits)
{
  char *p = (char*) out;
  int   host, net = bits / 8;

  memset (out, '\0', sizeof(*out));
  if (net > 0)
     memset (p, 0xFF, net);

  host = bits % 8;
  if (host > 0)
  {
    p[net] = 0xFF << (8 - host);
    memset (p+net+1, '\0', IN6ADDRSZ-net-1);
  }
  else
    memset (p+net, '\0', IN6ADDRSZ-net);
}

/**
 * Return a hex-string for an `in6_addr *mask`.
 * Should return the same as `ws_inet_ntop6()` without
 * the `::` shorthanding.
 */
const char *INET_util_in6_mask_str (const struct in6_addr *mask)
{
  static char buf [2*IN6ADDRSZ+1];
  char  *p = buf;
  int    i;

  for (i = 0; i < IN6ADDRSZ; i++)
  {
    const char *q = str_hex_byte (mask->s6_bytes[i]);

    *p++ = *q++;
    *p++ = *q;
  }
  *p = '\0';
  return strlwr (buf);
}

/**
 * Convert a string like '213.199.179.0-213.199.179.255' to CIDR notation '213.199.179/24'.
 *
 * \param[in]  str       The string to convert to CIDR form.
 * \param[out] ip4       The resulting `struct in_addr`.
 * \param[out] cidr_len  The resulting length of the CIDR network mask.
 *                       This is 0 if `str` is not on a `IPa-IPb` form.
 * \retval TRUE if `str` is valid.
 */
BOOL INET_util_get_CIDR_from_IPv4_string (const char *str, struct in_addr *ip4, int *cidr_len)
{
  struct in_addr a4_low, a4_high;
  char  *copy, *dash;
  size_t sz;

  sz = strlen(str) + 1;
  copy = alloca (sz);
  memcpy (copy, str, sz);

  /* For now, use these values
   */
  if (!stricmp(str, "LocalSubnet"))
  {
    *cidr_len = 0;
    memset (ip4, 0xFF, sizeof(*ip4));
    return (TRUE);
  }

  *cidr_len = 0;
  memset (ip4, '\0', sizeof(*ip4));

  dash = strchr (copy, '-');
  if (dash)
     *dash = '\0';

  if (ws_inet_pton(AF_INET, copy, &a4_low, NULL) != 1)
     return (FALSE);

  if (!dash)
  {
    *ip4 = a4_low;
    return (TRUE);
  }
  if (ws_inet_pton(AF_INET, dash+1, &a4_high, NULL) != 1)
     return (FALSE);

  *ip4 = a4_low;
  *cidr_len = 32 - INET_util_network_len32 (a4_high.s_addr, a4_low.s_addr);
  return (TRUE);
}

/**
 * Convert a string like 'fe80::/64' to CIDR notation.
 * Simplified version of the IPv4 version.
 *
 * \param[in]  str       The string to convert to CIDR form.
 * \param[out] ip6       The resulting `struct in6_addr`.
 * \param[out] cidr_len  The resulting length of the CIDR network mask.
 * \retval     TRUE if `str` is valid.
 */
BOOL INET_util_get_CIDR_from_IPv6_string (const char *str, struct in6_addr *ip6, int *cidr_len)
{
  struct in6_addr a6;
  char  *copy, *dash;
  size_t sz;

  sz = strlen(str) + 1;
  copy = alloca (sz);
  memcpy (copy, str, sz);

  /* For now, use these values
   */
  if (!stricmp(str, "LocalSubnet"))
  {
    *cidr_len = 0;
    memset (ip6, 0xFF, sizeof(*ip6));
    return (TRUE);
  }

  *cidr_len = 0;
  memset (ip6, '\0', sizeof(*ip6));

  dash = strchr (copy, '/');
  if (dash)
     *dash = '\0';

  if (ws_inet_pton(AF_INET6, copy, &a6, NULL) != 1)
     return (FALSE);

  *ip6 = a6;
  *cidr_len = dash ? atoi (dash+1) : 0;
  return (TRUE);
}

/**
 * Compare 2 IPv4-addresses; `addr1` and `addr2` considering `prefix_len`.
 *
 * \retval  0  if `addr1` is inside range of `addr2` block determined by `prefix_len`.
 * \retval  1  if `addr1` is above the range of `addr2`.
 * \retval -1  if `addr1` is below the range of `addr2`.
 */
int INET_util_range4cmp (const struct in_addr *addr1, const struct in_addr *addr2, int prefix_len)
{
  DWORD mask, start_ip, end_ip;

  if (prefix_len == 0)
  {
    start_ip = 0;
    end_ip   = DWORD_MAX;
  }
  else
  {
    mask = swap32 (0xFFFFFFFF << (32 - prefix_len));
    start_ip = addr2->s_addr & mask;
    end_ip   = start_ip | ~mask;
  }

  if (swap32(addr1->s_addr) < swap32(start_ip))
     return (-1);
  if (swap32(addr1->s_addr) > swap32(end_ip))
     return (1);
  return (0);
}

/**
 * Compare 2 IPv6-addresses; `addr1` and `addr2` considering `prefix_len`.
 *
 * \retval  0  if `addr1` is inside range of `addr2` block determined by `prefix_len`.
 * \retval  1  if `addr1` is above the range of `addr2`.
 * \retval -1  if `addr1` is below the range of `addr2`.
 */
int INET_util_range6cmp (const struct in6_addr *addr1, const struct in6_addr *addr2, int prefix_len)
{
  BYTE bytes = prefix_len / 8;
  BYTE bits  = prefix_len % 8;
  BYTE bmask = 0xFF << (8 - bits);
  int  rc    = memcmp (addr1, addr2, bytes);

  if (rc == 0)
  {
    int diff = (int)(addr1->s6_bytes[bytes] | bmask) - (int)(addr2->s6_bytes[bytes] | bmask);

    if (bits == 0 || diff == 0)
       return (0);
    rc = diff;
  }
  return (rc);
}

static const char *head_fmt = "%3s %-*s %-*s %-*s %-*s %s\n";
static const char *line_fmt = "%3d %-*s %-*s %-*s %-*s %s\n";

#define IP4_NET "69.208.0.0"
#define IP6_NET "2001:0db8::"

static void test_mask (int family, int start_ip_width, int ip_width, int cidr_width)
{
  struct in_addr  network4;
  struct in6_addr network6;
  int             i, bits, max_bits = (family == AF_INET6 ? 128 : 32);
  uint64          total_ips = U64_SUFFIX(0);
  const char     *total_str;
  char            network_str [MAX_IP6_SZ+1];
  BOOL lshift_prob = FALSE;

#if defined(__GNUC__)
  /**
   * The below code for `total_ips` shows some stange issues with
   * GCC and left shifts > 32. So just drop showing `total_ips`
   * for IPv6.
   */
  if (max_bits == 128)
     lshift_prob = TRUE;
  total_str = "";
#else
  total_str = "total";
#endif

  /**
   * Print an IPv6-address chunk like this:
   * `2001:0800::` (not like `2001:800::` which is default).
   */
  IPv6_leading_zeroes = 1;

  C_printf (head_fmt,       "bit",
            cidr_width,     "CIDR",
            start_ip_width, "start_ip",
            ip_width,       "end_ip",
            ip_width,       "mask",
            total_str);

  ws_inet_pton (AF_INET, IP4_NET, &network4, NULL);
  ws_inet_pton (AF_INET6, IP6_NET, &network6, NULL);
  ws_inet_ntop (family, (family == AF_INET6) ? (const void*)&network6 : (const void*)&network4,
                network_str, sizeof(network_str), NULL);

  for (bits = 0; bits <= max_bits; bits++)
  {
    char start_ip_str [MAX_IP6_SZ+1];
    char end_ip_str   [MAX_IP6_SZ+1];
    char mask_str     [MAX_IP6_SZ+1];
    char cidr_str     [MAX_IP6_SZ+11];

    if (!lshift_prob)
    {
      uint64 max64 = U64_SUFFIX(1) << (max_bits - bits);

      if (bits == max_bits)
           total_ips = 1;
      else if (max64 > U64_SUFFIX(0))
           total_ips = max64;
      else total_ips = QWORD_MAX;
    }

    if (family == AF_INET6)
    {
      struct in6_addr mask, start_ip, end_ip;

      INET_util_get_mask6 (&mask, bits);

      if (bits == 0)
      {
        /* A `mask` from `INET_util_get_mask6 (&mask, 0)` cannot be used here.
         */
        memset (&start_ip, '\0', sizeof(start_ip));
        memset (&end_ip, 0xFF, sizeof(end_ip));
      }
      else for (i = 0; i < IN6ADDRSZ; i++)
      {
        start_ip.s6_bytes[i] = network6.s6_bytes[i] & mask.s6_bytes[i];
        end_ip.s6_bytes[i]   = start_ip.s6_bytes[i] | ~mask.s6_bytes[i];
      }

      ws_inet_ntop (AF_INET6, &start_ip, start_ip_str, sizeof(start_ip_str), NULL);
      ws_inet_ntop (AF_INET6, &end_ip, end_ip_str, sizeof(end_ip_str), NULL);
      ws_inet_ntop (AF_INET6, &mask, mask_str, sizeof(mask_str), NULL);
    }
    else
    {
      struct in_addr mask, start_ip, end_ip;

      INET_util_get_mask4 (&mask, bits);

      if (bits == 0)
      {
        /**
         * A `mask` from `INET_util_get_mask4 (&mask, 0)` cannot be used here.
         */
        start_ip.s_addr = 0;
        end_ip.s_addr   = DWORD_MAX;
        total_ips       = DWORD_MAX;
      }
      else
      {
        start_ip.s_addr = network4.s_addr & mask.s_addr;
        end_ip.s_addr   = start_ip.s_addr | ~mask.s_addr;
        total_ips = swap32 (end_ip.s_addr) - swap32 (start_ip.s_addr) + 1;
      }

      ws_inet_ntop (AF_INET, &start_ip, start_ip_str, sizeof(start_ip_str), NULL);
      ws_inet_ntop (AF_INET, &end_ip, end_ip_str, sizeof(end_ip_str), NULL);
      ws_inet_ntop (AF_INET, &mask, mask_str, sizeof(mask_str), NULL);
    }

    if (lshift_prob)
         total_str = "";
    else if (total_ips >= QWORD_MAX)
         total_str = "Inf";
    else total_str = qword_str (total_ips);

    snprintf (cidr_str, sizeof(cidr_str), "%s/%u", network_str, bits);
    C_printf (line_fmt, bits,
              cidr_width, cidr_str,
              start_ip_width, start_ip_str,
              ip_width, end_ip_str,
              ip_width, mask_str,
              total_str);
  }
  IPv6_leading_zeroes = 0;
}

/**
 * Check that `INET_util_get_mask4()` is correct.
 *
 * Attempt to create a "Table of sample ranges" similar to this: \n
 *   https://www.mediawiki.org/wiki/Help:Range_blocks#Table
 */
void INET_util_test_mask4 (void)
{
  C_puts ("\nINET_util_test_mask4():\n");
  test_mask (AF_INET, (int)strlen(IP4_NET), (int)strlen("255.255.255.255"), (int)strlen(IP4_NET "/32"));
}

/**
 * Check that `INET_util_get_mask6()` is correct.
 *
 * Attempt to create a "Range Table" similar to this: \n
 *   https://www.mediawiki.org/wiki/Help:Range_blocks/IPv6#Range_table
 */
void INET_util_test_mask6 (void)
{
  C_puts ("\nINET_util_test_mask6():\n");
  test_mask (AF_INET6, (int)strlen(IP6_NET), MAX_IP6_SZ-7, (int)strlen(IP6_NET "/128"));
}

