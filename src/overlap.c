/**\file    overlap.c
 * \ingroup Main
 *
 * \brief
 *   Functions for dealing with overlapped operations in `WSA` functions.
 *   All Winsock function that this can apply to is:
 *     `AcceptEx()`, `ConnectEx()`, `DisconnectEx()`, `TransmitFile()`,
 *     `TransmitPackets()`, `WSARecv()`, `WSARecvFrom()`, `WSARecvMsg()`,
 *     `WSASend()`, `WSASendMsg()`, `WSASendTo()`, and `WSAIoctl()`.
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
#define TRACE(fmt, ...)                                    \
        do {                                               \
          if (g_cfg.trace_overlap >= 1 &&                  \
              g_cfg.trace_level >= g_cfg.trace_overlap)    \
          {                                                \
            trace_indent (g_cfg.trace_indent+2);           \
            trace_printf ("overlap.c(%u): " fmt, __LINE__, \
                          ## __VA_ARGS__);                 \
          }                                                \
        } while (0)

func_WSAGetOverlappedResult  p_WSAGetOverlappedResult = NULL;

/*
 * Structure for remembering a socket and an overlapped structure.
 * Used in overlapped send and receive to update the recv
 * and transmit counters in 'WSAGetOverlappedResult()'.
 */
struct overlapped {
       /*
        * TRUE:  this is an overlapped WSARecv() or WSARecvFrom().
        * FALSE: this an overlapped WSASend() or WSASendTo().
        */
       BOOL is_recv;

       /* Number of bytes expected in WSARecv() / WSARecvFrom() or
        * number of bytes given in WSASend() or WSASendTo().
        */
       DWORD bytes;

       /* The socket, event and overlapped pointer the call was issued with.
        */
       SOCKET         sock;
       WSAEVENT       event;
       WSAOVERLAPPED *ov;
     };

static smartlist_t *ov_list;
static DWORD        num_overlaps;

void overlap_exit (void)
{
  struct overlapped *ov;
  int    i, max = smartlist_len (ov_list);

  if (max >= 1)
  {
    TRACE ("%d overlapped transfers not completed:\n", max);
    for (i = 0; i < max; i++)
    {
      ov = smartlist_get (ov_list, i);
      TRACE ("  o: 0x%p, event: 0x%p, sock: %u, is_recv: %d, bytes: %lu\n",
             ov->ov, ov->event, SOCKET_CAST(ov->sock), ov->is_recv, DWORD_CAST(ov->bytes));
    }
    smartlist_wipe (ov_list, free);
  }
  else if (num_overlaps)
  {
    /* Print this only if we stored at least 1 overlap structure.
     */
    TRACE ("All overlapped transfers completed.\n");
  }
  num_overlaps = 0;
  ov_list = NULL;
}

void overlap_init (void)
{
  ov_list = smartlist_new();
}

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

void overlap_store (SOCKET s, WSAOVERLAPPED *o, DWORD num_bytes, BOOL is_recv)
{
  struct overlapped *ov = NULL;
  int    i, max = smartlist_len (ov_list);
  BOOL   modify = FALSE;

  TRACE ("o: 0x%p, event: 0x%p, sock: %u\n",
         o, o ? o->hEvent : NULL, SOCKET_CAST(s));

  for (i = 0; i < max; i++)
  {
    ov = smartlist_get (ov_list, i);
    if (ov->ov == o && ov->sock == s && ov->is_recv == is_recv)
    {
      modify = TRUE;
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

/*
 * Try to update all overlapped operations matching this event.
 */
void overlap_recall_all (const WSAEVENT *event)
{
  int i;

  for (i = 0; i < smartlist_len(ov_list); i++)
  {
    const struct overlapped *ov = smartlist_get (ov_list, i);
    DWORD bytes = 0;
    BOOL  rc    = FALSE;

    if (p_WSAGetOverlappedResult && ov->event == event)
    {
      ENTER_CRIT();
      rc = (*p_WSAGetOverlappedResult) (ov->sock, ov->ov, &bytes, 0, NULL);
      LEAVE_CRIT();

      if (rc)
      {
        /* This could reduce 'smartlist_len(ov_list)' by 1.
         */
        overlap_recall (ov->sock, ov->ov, bytes);
      }
    }
    if (i < smartlist_len(ov_list))
       TRACE ("ov_list[%d]: event: 0x%p, is_recv: %d, rc: %d, got %lu bytes.\n",
              i, ov->event, ov->is_recv, rc, DWORD_CAST(bytes));
    else
      TRACE ("ov_list[%d]: is_recv: %d, was recalled.\n", i, ov->is_recv);
  }
}

/*
 * Match the socket 's' and 'o' value against a previous overlapped
 * 'WSARecvXX()' / 'WSASendXX()' and update the 'g_cfg.counts.recv_bytes'
 * or 'g_cfg.counts.send_bytes' statistics with the 'bytes' value.
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
      g_cfg.counts.recv_bytes += bytes;
      TRACE ("ov_list[%d]: room for %lu bytes, got %lu bytes.\n",
             i, DWORD_CAST(ov->bytes), DWORD_CAST(bytes));
    }
    else
    {
      g_cfg.counts.send_bytes += bytes;
      TRACE ("ov_list[%d]: sent %lu bytes, actual sent %lu bytes.\n",
             i, DWORD_CAST(ov->bytes), DWORD_CAST(bytes));
    }
    free (ov);
    smartlist_del (ov_list, i);
    break;
  }
}

/*
 * Remove an overlap entry matching socket 's'.
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
