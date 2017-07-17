#ifndef _OVERLAP_H
#define _OVERLAP_H

typedef BOOL (WINAPI *func_WSAGetOverlappedResult) (
                           SOCKET         s,
                           WSAOVERLAPPED *ov,
                           DWORD         *transfered,
                           BOOL           wait,
                           DWORD         *flags);

extern func_WSAGetOverlappedResult p_WSAGetOverlappedResult;

extern int  overlap_init (void);
extern void overlap_exit (void);

extern void overlap_store (SOCKET s, WSAOVERLAPPED *ov, DWORD num_bytes, BOOL is_recv);
extern void overlap_recall (SOCKET s, const WSAOVERLAPPED *ov, DWORD bytes);
extern void overlap_recall_all (const WSAEVENT *ev);
extern void overlap_remove (SOCKET s);

#endif /* _OVERLAP_H */
