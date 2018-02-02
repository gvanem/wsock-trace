#ifndef _SMARTLIST_H
#define _SMARTLIST_H

/*
 * From Tor's src/common/container.h:
 *
 * A resizeable list of pointers, with associated helpful functionality.
 *
 * The members of this struct are exposed only when 'EXPOSE_SMARTLIST_DETAILS'
 * is defined (like inside common.c). Otherwise all access to smartlist
 * internals should go through the functions defined below.
 */
#if defined(EXPOSE_SMARTLIST_DETAILS)
  typedef struct smartlist_t {
          /*
           * 'list' (of anything) has enough capacity to store exactly 'capacity'
           * elements before it needs to be resized. Only the first 'num_used'
           * (<= capacity) elements point to valid data.
           */
          void **list;
          int    num_used;
          int    capacity;
        } smartlist_t;
#else
  typedef struct smartlist_internal smartlist_t; /* Opaque struct */
#endif

typedef void (MS_CDECL *smartlist_parse_func) (smartlist_t *sl, const char *line);

extern smartlist_t *smartlist_new (void);
extern int          smartlist_len (const smartlist_t *sl);
extern void        *smartlist_get (const smartlist_t *sl, int idx);
extern void         smartlist_free (smartlist_t *sl);
extern void         smartlist_ensure_capacity (smartlist_t *sl, size_t num);
extern void         smartlist_add (smartlist_t *sl, void *element);
extern void         smartlist_del (smartlist_t *sl, int idx);
extern void         smartlist_del_keeporder (smartlist_t *sl, int idx);
extern void         smartlist_insert (smartlist_t *sl, int idx, void *val);
extern void         smartlist_append (smartlist_t *sl1, const smartlist_t *sl2);
extern void         smartlist_sort (smartlist_t *sl, int (*compare)(const void **a, const void **b));
extern smartlist_t *smartlist_read_file (const char *file, smartlist_parse_func parse, BOOL parse_raw);

extern int   smartlist_bsearch_idx (const smartlist_t *sl, const void *key,
                                    int (*compare)(const void *key, const void **member),
                                    int *found_out);

extern void *smartlist_bsearch (const smartlist_t *sl, const void *key,
                                int (*compare)(const void *key, const void **member));

#endif  /* _SMARTLIST_H */
