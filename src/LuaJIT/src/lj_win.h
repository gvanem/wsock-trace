#if defined(LUA_BUILD_AS_DLL)
  #define LJ_TRACE_API __declspec(dllexport)
#else
  #define LJ_TRACE_API extern
#endif

#if defined(_WIN32)
  #include <stdio.h>

  LJ_TRACE_API int         ljit_trace_init (void);
  LJ_TRACE_API int        *ljit_trace_level (void);
  LJ_TRACE_API void        ljit_set_color (int color);
  LJ_TRACE_API void        ljit_restore_color (void);
  LJ_TRACE_API const char *ljit_basename (const char *fname);

  #define LJ_TRACE(level, fmt, ...)                       \
          do {                                            \
            if (ljit_trace_init() >= level) {             \
              ljit_set_color (1);                         \
              printf ("LuaJIT: %s(%u): ",                 \
                      ljit_basename(__FILE__), __LINE__); \
              printf (fmt, ##__VA_ARGS__);                \
              ljit_restore_color();                       \
            }                                             \
          } while (0)

#else
  #define LJ_TRACE(level, fmt, ...)   ((void)0)
#endif  /* _WIN32 */

