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

#endif  /* !WIN_SYS_QUEUE_H */

