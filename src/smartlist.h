#ifndef _SMARTLIST_H
#define _SMARTLIST_H

/**\file    smartlist.h
 * \ingroup Misc
 *
 * \brief
 * A resizeable list of pointers, with associated helpful functionality.
 * Taken from Tor's src/common/container.h and modified.
 */
#if defined(EXPOSE_SMARTLIST_DETAILS) || defined(__DOXYGEN__)
  /**
   * \typedef smartlist_t
   * The members of this struct are exposed only when `EXPOSE_SMARTLIST_DETAILS`
   * is set inside smartlist.c. Otherwise all access to smartlist internals
   * should go through the functions defined below.
   */
  typedef struct smartlist_t {
          /**
           * `list` (of anything) has enough capacity to store exactly `capacity`
           * elements before it needs to be resized. Only the first `num_used`
           * (<= `capacity`) elements point to valid data.
           */
          void **list;
          int    num_used;
          int    capacity;
        } smartlist_t;
#else
  typedef struct smartlist_internal smartlist_t; /* Opaque struct */
#endif

/**\typedef smartlist_sort_func
 * A function used to compare smartlist elements must match this type.
 */
typedef int (*smartlist_sort_func) (const void **a, const void **b);

/**\typedef smartlist_parse_func
 * A function used to parse lines from a text-file must match this type.
 */
typedef void (*smartlist_parse_func) (smartlist_t *sl, const char *line);

#if defined(_CRTDBG_MAP_ALLOC)
  extern smartlist_t *_smartlist_new (const char *file, unsigned line);
  extern void          smartlist_leak_check (void);

  #define smartlist_new() _smartlist_new (__FILE__, __LINE__)
#else
  extern smartlist_t *smartlist_new (void);
#endif

extern int          smartlist_len (const smartlist_t *sl);
extern void        *smartlist_get (const smartlist_t *sl, int idx);
extern void         smartlist_free (smartlist_t *sl);
extern void         smartlist_wipe (smartlist_t *sl, void (*free_fn)(void *a));
extern void         smartlist_ensure_capacity (smartlist_t *sl, size_t num);
extern void         smartlist_add (smartlist_t *sl, void *element);
extern void         smartlist_del (smartlist_t *sl, int idx);
extern void         smartlist_del_keeporder (smartlist_t *sl, int idx);
extern void         smartlist_insert (smartlist_t *sl, int idx, void *val);
extern void         smartlist_append (smartlist_t *sl1, const smartlist_t *sl2);
extern void         smartlist_sort (smartlist_t *sl, smartlist_sort_func compare);
extern int          smartlist_duplicates (smartlist_t *sl, smartlist_sort_func compare);
extern int          smartlist_make_uniq (smartlist_t *sl, smartlist_sort_func compare, void (*free_fn)(void *a));
extern smartlist_t *smartlist_read_file (const char *file, smartlist_parse_func parse);

extern int   smartlist_bsearch_idx (const smartlist_t *sl, const void *key,
                                    int (*compare)(const void *key, const void **member),
                                    int *found_out);

extern void *smartlist_bsearch (const smartlist_t *sl, const void *key,
                                int (*compare)(const void *key, const void **member));

#endif  /* _SMARTLIST_H */
