/*
 * Based on:
 *  https://gist.github.com/Myriachan/2ee3b11e7e0de4007a574a53f506c2f8
 *
 * Compile & link:
 *   MSVC:  cl -nologo -W3 -Fe./AFUnix-issue.exe AFUnix-issue.c
 *   MinGW: gcc -o AFUnix-issue.exe AFUnix-issue.c -lws2_32
 */

#define _WIN32_WINNT 0x0A00   /* For '_MSC_VER' */
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#ifdef _MSC_VER
  #include <afunix.h>

  #ifdef USE_WSOCK_TRACE
    #pragma comment (lib, "wsock_trace.lib")
  #else
    #pragma comment (lib, "ws2_32.lib")
  #endif

#elif defined(__MINGW32__)
  #define AF_UNIX         1
  #define SIO_AF_UNIX_GETPEERPID  _WSAIOR(IOC_VENDOR, 256) /* Returns ULONG PID of the connected peer process */

  #define UNIX_PATH_MAX   108

  struct sockaddr_un {
         unsigned short sun_family;                 /* address family AF_LOCAL/AF_UNIX */
         char           sun_path [UNIX_PATH_MAX];   /* room for socket address */
       };
#endif

#define SUN_FILE  "AFUnixIoctlIssue.pipe"

int main (void)
{
  struct sockaddr_un address;
  WSADATA wsadata;

  WSAStartup (MAKEWORD(2, 2), &wsadata);

  DeleteFile (SUN_FILE);

  memset (&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  strcpy (address.sun_path, SUN_FILE);

  int    addressSize = offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1;
  SOCKET listener = socket (AF_UNIX, SOCK_STREAM, 0);

  if (listener == INVALID_SOCKET)
  {
    printf ("socket 1 failed: %d\n", WSAGetLastError());
    return 1;
  }

  if (bind(listener, (const struct sockaddr*)&address, addressSize) != 0)
  {
    printf ("bind failed: %d\n", WSAGetLastError());
    return 1;
  }

  if (listen(listener, 5) != 0)
  {
    printf ("listen failed: %d\n", WSAGetLastError());
    return 1;
  }

  SOCKET connector = socket (AF_UNIX, SOCK_STREAM, 0);
  if (connector == INVALID_SOCKET)
  {
    printf ("socket 2 failed: %d\n", WSAGetLastError());
    return 1;
  }

  // Use non-blocking so that connect will never block on accept being called.
  // That shouldn't happen normally, but don't rely on that behavior.
  u_long yes = 1;
  if (ioctlsocket(connector, FIONBIO, &yes) != 0)
  {
    printf ("ioctlsocket failed: %d\n", WSAGetLastError());
    return 1;
  }

  if (connect(connector, (const struct sockaddr*)&address, addressSize) != 0)
  {
    if (WSAGetLastError() != WSAEWOULDBLOCK)
    {
      printf ("connect failed: %d\n", WSAGetLastError());
      return 1;
    }
  }

  struct sockaddr_un acceptedAddress;
  int    acceptedAddressSize = sizeof(acceptedAddress);
  SOCKET accepted = accept (listener, (struct sockaddr*)&acceptedAddress, &acceptedAddressSize);

  if (accepted == INVALID_SOCKET)
  {
    printf ("accept failed: %d\n", WSAGetLastError());
    return 1;
  }

  puts ("socket established");

  // Don't bother waiting; if it fails, whatever.
  send (connector, "kitty", 5, 0);

  printf ("pid: %lu\n", GetCurrentProcessId());

  u_long kitty;
  DWORD  kittySize = 0xCCCCCCCC;
  int    kittyResult = WSAIoctl (accepted, FIONREAD, NULL, 0, &kitty, sizeof(kitty), &kittySize, NULL, NULL);

  printf ("kitty: %d %lu %lu\n", kittyResult, kitty, kittySize);

  u_long meow;
  DWORD  meowSize = 0xCCCCCCCC;
  int    meowResult = WSAIoctl (accepted, SIO_AF_UNIX_GETPEERPID, NULL, 0, &meow, sizeof(meow), &meowSize, NULL, NULL);

  printf ("meow: %d %lu %lu\n", meowResult, meow, meowSize);

  closesocket (listener);
  closesocket (connector);
  closesocket (accepted);

  return 0;
}
