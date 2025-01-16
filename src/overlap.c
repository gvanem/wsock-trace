/**\file    overlap.c
 * \ingroup Main
 *
 * \brief
 *   Functions for dealing with overlapped operations in `WSA` functions.
 *   All Winsock function that this can apply to is: <br>
 *     `AcceptEx()`, `ConnectEx()`, `DisconnectEx()`, `TransmitFile()`,
 *     `TransmitPackets()`, `WSARecv()`, `WSARecvFrom()`, `WSARecvMsg()`, `WSASend()`, <br>
 *     `WSASendMsg()`, `WSASendTo()`, and `WSAIoctl()`.
 *
 * Allthough Wsock-Trace does support only a few of these.
 */

#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "init.h"
#include "smartlist.h"
#include "overlap.h"

#undef  TRACE
#define TRACE(fmt, ...)                                 \
        do {                                            \
          if (g_cfg.trace_overlap >= 1 &&               \
              g_cfg.trace_level >= g_cfg.trace_overlap) \
          {                                             \
            C_indent (g_cfg.trace_indent+2);            \
            C_printf ("overlap.c(%u): " fmt, __LINE__,  \
                      ## __VA_ARGS__);                  \
          }                                             \
        } while (0)

func_WSAGetOverlappedResult  p_WSAGetOverlappedResult = NULL;

static char ov_trace_buf [200];

/** \struct overlapped
 *
 * Structure for remembering a socket and an overlapped structure.
 * Used in overlapped send and receive to update the recv
 * and transmit counters in `WSAGetOverlappedResult()`.
 */
struct overlapped {
       /**
        * \li `true:`  this is an overlapped `WSARecv()` or `WSARecvFrom()`.
        * \li `false:` this an overlapped `WSASend()` or `WSASendTo()`.
        */
       bool is_recv;

       /**
        * Max number of bytes expected in `WSARecv()` / `WSARecvFrom()` or <br>
        * number of bytes given in `WSASend()` or `WSASendTo()`.
        */
       DWORD bytes;

       /**
        * The socket, event and overlapped pointer the call was issued with.
        */
       SOCKET         sock;
       WSAEVENT       event;
       WSAOVERLAPPED *ov;
     };

static smartlist_t *ov_list;       /**< The dynamic list of `struct overlapped` */
static DWORD        num_overlaps;  /**< Number of overlapped operations pending */

/**
 * \li Report any non-completed overlapped operations.
 * \li Free the memory allocated for the overlapped list.
 * \li Called from `wsock_trace_exit()`.
 */
void overlap_exit (void)
{
  struct overlapped *ov;
  int    i, max;

  if (!ov_list)
     return;

  max = smartlist_len (ov_list);
  if (max >= 1)
  {
    TRACE ("%d overlapped transfers not completed:\n", max);
    for (i = 0; i < max; i++)
    {
      ov = smartlist_get (ov_list, i);
      TRACE ("  o: 0x%p, event: 0x%p, sock: %u, is_recv: %d, bytes: %lu\n",
             ov->ov, ov->event, SOCKET_CAST(ov->sock), ov->is_recv, ov->bytes);
    }
  }
  else if (num_overlaps)
  {
    /* Print this only if we stored at least 1 overlap structure.
     */
    TRACE ("All overlapped transfers completed.\n");
  }
  num_overlaps = 0;
  smartlist_wipe (ov_list, free);
  ov_list = NULL;
}

/**
 * Initialiser for overlapped operations.
 * Just create the dynamic list.
 */
void overlap_init (void)
{
  ov_list = smartlist_new();
}

/**
 * Trace an overlapped operation:
 * \li if `i == -1`, trace all elements in the list.
 * \li if `i != -1`, trace the element with index `i`.
 */
static void overlap_trace (int i, const struct overlapped *ov)
{
  if (i == -1)
  {
    int max = smartlist_len (ov_list);

    for (i = 0; i < max; i++)
    {
      ov = smartlist_get (ov_list, i);
      TRACE ("ov_list[%d]: is_recv: %d, event: 0x%p, sock: %u\n",
             i, ov->is_recv, ov->event, (unsigned)ov->sock);
    }
  }
  else
    TRACE ("ov_list[%d]: is_recv: %d, event: 0x%p, sock: %u\n",
           i, ov->is_recv, ov->event, SOCKET_CAST(ov->sock));
}

/**
 * Remember an overlapped operation for `overlap_recall()`.
 *
 * \param[in] s          The socket for this overlapped operation.
 * \param[in] o          The overlapped structure itself.
 * \param[in] num_bytes  The number of bytes in the array of `WSABUF` structure the operlapping function was called with.
 * \param[in] is_recv    true: We were called from `WSARecv()` or `WSARecvFrom()`.
 *                       false: We were called from `WSASend()` or `WSASendTo()`.
 */
void overlap_store (SOCKET s, WSAOVERLAPPED *o, DWORD num_bytes, bool is_recv)
{
  struct overlapped *ov = NULL;
  int    i, max = smartlist_len (ov_list);
  bool   modify = false;

  TRACE ("o: 0x%p,  event: 0x%p, sock: %u\n",
         o, o ? o->hEvent : NULL, SOCKET_CAST(s));

  for (i = 0; i < max; i++)
  {
    ov = smartlist_get (ov_list, i);
    if (ov->ov == o && ov->sock == s && ov->is_recv == is_recv)
    {
      modify = true;
      break;
    }
  }

  if (!modify)
  {
    ov = malloc (sizeof(*ov));
    if (!ov)
       return;
    ov->is_recv = is_recv;
    ov->sock    = s;
    ov->ov      = o;
    smartlist_add (ov_list, ov);
    num_overlaps++;
  }

  ov->event = o ? o->hEvent : NULL;
  ov->bytes = num_bytes;
  overlap_trace (-1, NULL);
}

/**
 * Try to update all overlapped operations matching this event.
 */
void overlap_recall_all (const WSAEVENT *event)
{
  int i;

  for (i = 0; i < smartlist_len(ov_list); i++)
  {
    const struct overlapped *ov = smartlist_get (ov_list, i);
    DWORD bytes = 0;
    bool  rc    = false;

    if (p_WSAGetOverlappedResult && ov->event == event)
    {
      ENTER_CRIT();
      rc = (*p_WSAGetOverlappedResult) (ov->sock, ov->ov, &bytes, 0, NULL);
      LEAVE_CRIT (0);

      if (rc)
      {
        /* This could reduce 'smartlist_len(ov_list)' by 1.
         */
        overlap_recall (ov->sock, ov->ov, bytes);
      }
    }
    if (i < smartlist_len(ov_list))
       TRACE ("ov_list[%d]: event: 0x%p, is_recv: %d, rc: %d, got %lu bytes.\n",
              i, ov->event, ov->is_recv, rc, bytes);
    else
      TRACE ("ov_list[%d]: is_recv: %d, was recalled.\n", i, ov->is_recv);
  }
}

/**
 * Match the socket `s` and overlapped pointer `o` against a previous overlapped
 * `WSARecvXX()` / `WSASendXX()` call.
 *
 * And do update the `g_data.counts.recv_bytes`
 * or `g_data.counts.send_bytes` statistics with the `bytes` value.
 */
void overlap_recall (SOCKET s, const WSAOVERLAPPED *o, DWORD bytes)
{
  int i, max = smartlist_len (ov_list);

  for (i = 0; i < max; i++)
  {
    struct overlapped *ov = smartlist_get (ov_list, i);

    overlap_trace (i, ov);

    if (ov->ov != o || ov->sock != s)
       continue;

    if (ov->is_recv)
    {
      g_data.counts.recv_bytes += bytes;
      TRACE ("ov_list[%d]: room for %lu bytes, got %lu bytes.\n", i, ov->bytes, bytes);
    }
    else
    {
      g_data.counts.send_bytes += bytes;
      TRACE ("ov_list[%d]: sent %lu bytes, actual sent %lu bytes.\n", i, ov->bytes, bytes);
    }
    free (ov);
    smartlist_del (ov_list, i);
    break;
  }
}

/**
 * Remove an overlap entry matching socket `s`.
 */
void overlap_remove (SOCKET s)
{
  int i, max;

  /* This if-test should not be needed. It would mean 'closesocket()' was called
   * after 'wsock_trace_exit()'.
   */
  if (!ov_list)
     return;

  max = smartlist_len (ov_list);
  for (i = 0; i < max; i++)
  {
    struct overlapped *ov = smartlist_get (ov_list, i);

    if (ov->sock != s)
       continue;

    free (ov);
    smartlist_del (ov_list, i);
    max--;
    i--;
  }
  overlap_trace (-1, NULL);
}

/**
 * Return a pointer to the trace buffer.
 */
char *overlap_trace_buf (void)
{
  return (ov_trace_buf);
}

/**
 * Get the transfer count of an overlapped operation.
 */
bool overlap_transferred (SOCKET s, const WSAOVERLAPPED *ov, DWORD *transferred)
{
  WSAOVERLAPPED ov_copy;
  char  err_buf [150] = "None";
  DWORD flags = 0;
  bool  completed = false;
  bool  rc = false;

  *transferred = 0;
  ov_trace_buf[0] = '\0';

  if (p_WSAGetOverlappedResult && HasOverlappedIoCompleted(ov))
  {
    ENTER_CRIT();
    completed = true;
    ov_copy = *ov;
    rc = (*p_WSAGetOverlappedResult) (s, &ov_copy, transferred, FALSE, &flags);
    LEAVE_CRIT (0);
  }
  if (!rc)
     ws_strerror ((*g_data.WSAGetLastError)(), err_buf, sizeof(err_buf));

  if (g_cfg.trace_overlap >= 1 && g_cfg.trace_level >= g_cfg.trace_overlap)
  {
    snprintf (ov_trace_buf, sizeof(ov_trace_buf),
              "%*soverlap.c(%u): rc: %d, sock: %u, ov: 0x%p, transferred: %lu, err: %s, completed: %d\n",
              g_cfg.trace_indent+2, "", __LINE__, rc, (unsigned int)s, ov, *transferred,
              err_buf, completed);
  }
  return (rc && completed);
}
