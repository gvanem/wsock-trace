#ifndef WIN_SYS_QUEUE_H
#define WIN_SYS_QUEUE_H

/*
 * A minimal version of '<sys/queue.h>' for libloc on Windows.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 */

#define TAILQ_HEAD(name, type)                                    \
        struct name {                                             \
          struct type *tqh_first; /* first element */             \
          struct type **tqh_last; /* addr of last next element */ \
        }

#define TAILQ_ENTRY(type)                                                \
        struct {                                                         \
          struct type *tqe_next;  /* next element */                     \
          struct type **tqe_prev; /* address of previous next element */ \
        }

#define TAILQ_FIRST(head)   ((head)->tqh_first)
#define TAILQ_END(head)     NULL
#define TAILQ_EMPTY(head)   (TAILQ_FIRST(head) == TAILQ_END(head))

#define TAILQ_INIT(head) do {                    \
          (head)->tqh_first = NULL;              \
          (head)->tqh_last = &(head)->tqh_first; \
        } while (0)

#define TAILQ_INSERT_TAIL(head, elm, field) do {     \
          (elm)->field.tqe_next = NULL;              \
          (elm)->field.tqe_prev = (head)->tqh_last;  \
          *(head)->tqh_last = (elm);                 \
          (head)->tqh_last = &(elm)->field.tqe_next; \
        } while (0)

#define TAILQ_REMOVE(head, elm, field) do {               \
          if ((elm)->field.tqe_next)                      \
             (elm)->field.tqe_next->field.tqe_prev =      \
               (elm)->field.tqe_prev;                     \
          else (head)->tqh_last = (elm)->field.tqe_prev;  \
          *(elm)->field.tqe_prev = (elm)->field.tqe_next; \
        } while (0)

#if 0  // not needed
  #define TAILQ_HEAD_INITIALIZER(head)  { NULL, &(head).tqh_first }

  #define TAILQ_NEXT(elm, field)        ((elm)->field.tqe_next)

  #define TAILQ_LAST(head, headname)                                      \
          (*(((struct headname *)((head)->tqh_last))->tqh_last))

  #define TAILQ_PREV(elm, headname, field)                                \
          (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))

  #define TAILQ_FOREACH(var, head, field)                                 \
          for((var) = TAILQ_FIRST(head);                                  \
              (var) != TAILQ_END(head);                                   \
              (var) = TAILQ_NEXT(var, field))

  #define TAILQ_FOREACH_SAFE(var, head, field, tvar)                      \
          for ((var) = TAILQ_FIRST((head));                               \
               (var) && ((tvar) = TAILQ_NEXT((var), field), 1);           \
               (var) = (tvar))

  #define TAILQ_FOREACH_REVERSE(var, head, field, headname)               \
          for((var) = TAILQ_LAST(head, headname);                         \
              (var) != TAILQ_END(head);                                   \
              (var) = TAILQ_PREV(var, headname, field))

  #define TAILQ_FOREACH_REVERSE_SAFE(var, head, field, headname, tvar)    \
          for ((var) = TAILQ_LAST((head), headname);                      \
               (var) && ((tvar) = TAILQ_PREV((var), headname, field), 1); \
               (var) = (tvar))

  #define TAILQ_INSERT_HEAD(head, elm, field) do {                        \
            if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)      \
                 (head)->tqh_first->field.tqe_prev =                      \
                       &(elm)->field.tqe_next;                            \
            else (head)->tqh_last = &(elm)->field.tqe_next;               \
            (head)->tqh_first = (elm);                                    \
            (elm)->field.tqe_prev = &(head)->tqh_first;                   \
          } while (0)

  #define TAILQ_INSERT_AFTER(head, listelm, elm, field) do {                 \
            if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL) \
                 (elm)->field.tqe_next->field.tqe_prev =                     \
                    &(elm)->field.tqe_next;                                  \
            else (head)->tqh_last = &(elm)->field.tqe_next;                  \
            (listelm)->field.tqe_next = (elm);                               \
            (elm)->field.tqe_prev = &(listelm)->field.tqe_next;              \
          } while (0)

  #define TAILQ_INSERT_BEFORE(listelm, elm, field) do {         \
            (elm)->field.tqe_prev = (listelm)->field.tqe_prev;  \
            (elm)->field.tqe_next = (listelm);                  \
            *(listelm)->field.tqe_prev = (elm);                 \
            (listelm)->field.tqe_prev = &(elm)->field.tqe_next; \
          } while (0)

  #define TAILQ_REPLACE(head, elm, elm2, field) do {                      \
            if (((elm2)->field.tqe_next = (elm)->field.tqe_next) != NULL) \
                 (elm2)->field.tqe_next->field.tqe_prev =                 \
                   &(elm2)->field.tqe_next;                               \
            else (head)->tqh_last = &(elm2)->field.tqe_next;              \
            (elm2)->field.tqe_prev = (elm)->field.tqe_prev;               \
            *(elm2)->field.tqe_prev = (elm2);                             \
          } while (0)
#endif

#endif  /* !WIN_SYS_QUEUE_H */

