/*
glib_compat.c replacement functionality for glib code used in qemu
Copyright (C) 2016 Chris Eagle cseagle at gmail dot com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// Part of this code was lifted from glib-2.28.0.
// Glib license is available in COPYING_GLIB file in root directory.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "glib_compat.h"

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#ifndef _WIN64
#define GPOINTER_TO_UINT(p) ((guint)(uintptr_t)(p))
#else
#define GPOINTER_TO_UINT(p) ((guint) (guint64) (p))
#endif
#define G_MAXINT    INT_MAX

/* All functions below added to eliminate GLIB dependency */

/* hashing and equality functions */
// Hash functions lifted glib-2.28.0/glib/ghash.c

/**
 * g_direct_hash:
 * @v: a #gpointer key
 *
 * Converts a gpointer to a hash value.
 * It can be passed to g_hash_table_new() as the @hash_func parameter,
 * when using pointers as keys in a #GHashTable.
 *
 * Returns: a hash value corresponding to the key.
 */
guint g_direct_hash (gconstpointer v)
{
  return GPOINTER_TO_UINT (v);
}

/**
 * g_direct_equal:
 * @v1: a key.
 * @v2: a key to compare with @v1.
 *
 * Compares two #gpointer arguments and returns %TRUE if they are equal.
 * It can be passed to g_hash_table_new() as the @key_equal_func
 * parameter, when using pointers as keys in a #GHashTable.
 *
 * Returns: %TRUE if the two keys match.
 */
gboolean
g_direct_equal (gconstpointer v1,
    gconstpointer v2)
{
  return v1 == v2;
}

// g_str_hash() is lifted glib-2.28.0/glib/gstring.c
/**
 * g_str_hash:
 * @v: a string key
 *
 * Converts a string to a hash value.
 *
 * This function implements the widely used "djb" hash apparently posted
 * by Daniel Bernstein to comp.lang.c some time ago.  The 32 bit
 * unsigned hash value starts at 5381 and for each byte 'c' in the
 * string, is updated: <literal>hash = hash * 33 + c</literal>.  This
 * function uses the signed value of each byte.
 *
 * It can be passed to g_hash_table_new() as the @hash_func parameter,
 * when using strings as keys in a #GHashTable.
 *
 * Returns: a hash value corresponding to the key
 **/
guint g_str_hash (gconstpointer v)
{
  const signed char *p;
  guint32 h = 5381;

  for (p = v; *p != '\0'; p++)
    h = (h << 5) + h + *p;

  return h;
}

gboolean g_str_equal(gconstpointer v1, gconstpointer v2)
{
   return strcmp((const char*)v1, (const char*)v2) == 0;
}

/**
 * g_str_has_suffix:
 * @str: a nul-terminated string.
 * @suffix: the nul-terminated suffix to look for.
 *
 * Looks whether the string @str ends with @suffix.
 *
 * Return value: %TRUE if @str end with @suffix, %FALSE otherwise.
 *
 * Since: 2.2
 **/
gboolean
g_str_has_suffix(const gchar *str, const gchar *suffix)
{
  int str_len;
  int suffix_len;

  if (str == NULL || suffix == NULL) {
    return FALSE;
  }

  str_len = strlen (str);
  suffix_len = strlen (suffix);

  if (str_len < suffix_len)
    return FALSE;

  return strcmp (str + str_len - suffix_len, suffix) == 0;
}

/**
 * g_str_has_prefix:
 * @str: a nul-terminated string.
 * @prefix: the nul-terminated prefix to look for.
 *
 * Looks whether the string @str begins with @prefix.
 *
 * Return value: %TRUE if @str begins with @prefix, %FALSE otherwise.
 *
 * Since: 2.2
 **/
gboolean
g_str_has_prefix(const gchar *str, const gchar *prefix)
{
  int str_len;
  int prefix_len;

  if (str == NULL || prefix == NULL) {
    return FALSE;
  }

  str_len = strlen (str);
  prefix_len = strlen (prefix);

  if (str_len < prefix_len)
    return FALSE;

  return strncmp (str, prefix, prefix_len) == 0;
}

// g_int_hash() is lifted from glib-2.28.0/glib/gutils.c
/**
 * g_int_hash:
 * @v: a pointer to a #gint key
 *
 * Converts a pointer to a #gint to a hash value.
 * It can be passed to g_hash_table_new() as the @hash_func parameter,
 * when using pointers to integers values as keys in a #GHashTable.
 *
 * Returns: a hash value corresponding to the key.
 */
guint g_int_hash (gconstpointer v)
{
  return *(const gint*) v;
}

gboolean g_int_equal(gconstpointer v1, gconstpointer v2)
{
   return *((const gint*)v1) == *((const gint*)v2);
}

/**
 * g_int64_hash:
 * @v: a pointer to a #gint64 key
 *
 * Converts a pointer to a #gint64 to a hash value.
 *
 * It can be passed to g_hash_table_new() as the @hash_func parameter,
 * when using non-%NULL pointers to 64-bit integer values as keys in a
 * #GHashTable.
 *
 * Returns: a hash value corresponding to the key.
 *
 * Since: 2.22
 */
guint
g_int64_hash (gconstpointer v)
{
  return (guint) *(const gint64*) v;
}

/**
 * g_int64_equal:
 * @v1: a pointer to a #gint64 key
 * @v2: a pointer to a #gint64 key to compare with @v1
 *
 * Compares the two #gint64 values being pointed to and returns
 * %TRUE if they are equal.
 * It can be passed to g_hash_table_new() as the @key_equal_func
 * parameter, when using non-%NULL pointers to 64-bit integers as keys in a
 * #GHashTable.
 *
 * Returns: %TRUE if the two keys match.
 *
 * Since: 2.22
 */
gboolean
g_int64_equal (gconstpointer v1,
               gconstpointer v2)
{
  return *((const gint64*) v1) == *((const gint64*) v2);
}

/* Doubly-linked list */

GList *g_list_first(GList *list)
{
   if (list == NULL) return NULL;
   while (list->prev) list = list->prev;
   return list;
}

void g_list_foreach(GList *list, GFunc func, gpointer user_data)
{
   GList *lp;
   for (lp = list; lp; lp = lp->next) {
      (*func)(lp->data, user_data);
   }
}

void g_list_free(GList *list)
{
   GList *lp, *next, *prev = NULL;
   if (list) prev = list->prev;
   for (lp = list; lp; lp = next) {
      next = lp->next;
      free(lp);
   }
   for (lp = prev; lp; lp = prev) {
      prev = lp->prev;
      free(lp);
   }
}

/**
 * g_list_free_full:
 * @list: a pointer to a #GList
 * @free_func: the function to be called to free each element's data
 *
 * Convenience method, which frees all the memory used by a #GList, and
 * calls the specified destroy function on every element's data.
 *
 * Since: 2.28
 */
void
g_list_free_full (GList          *list,
      GDestroyNotify  free_func)
{
  g_list_foreach (list, (GFunc) free_func, NULL);
  g_list_free (list);
}

/**
 * g_list_last:
 * @list: a #GList
 *
 * Gets the last element in a #GList.
 *
 * Returns: the last element in the #GList,
 *     or %NULL if the #GList has no elements
 */
GList*
g_list_last (GList *list)
{
  if (list)
    {
      while (list->next)
  list = list->next;
    }

  return list;
}

/**
 * g_list_append:
 * @list: a pointer to a #GList
 * @data: the data for the new element
 *
 * Adds a new element on to the end of the list.
 *
 * <note><para>
 * The return value is the new start of the list, which
 * may have changed, so make sure you store the new value.
 * </para></note>
 *
 * <note><para>
 * Note that g_list_append() has to traverse the entire list
 * to find the end, which is inefficient when adding multiple
 * elements. A common idiom to avoid the inefficiency is to prepend
 * the elements and reverse the list when all elements have been added.
 * </para></note>
 *
 * |[
 * /&ast; Notice that these are initialized to the empty list. &ast;/
 * GList *list = NULL, *number_list = NULL;
 *
 * /&ast; This is a list of strings. &ast;/
 * list = g_list_append (list, "first");
 * list = g_list_append (list, "second");
 *
 * /&ast; This is a list of integers. &ast;/
 * number_list = g_list_append (number_list, GINT_TO_POINTER (27));
 * number_list = g_list_append (number_list, GINT_TO_POINTER (14));
 * ]|
 *
 * Returns: the new start of the #GList
 */
GList*
g_list_append (GList  *list,
         gpointer  data)
{
  GList *new_list;
  GList *last;

  new_list = g_new0(GList, 1);
  new_list->data = data;
  new_list->next = NULL;

  if (list)
    {
      last = g_list_last (list);
      /* g_assert (last != NULL); */
      last->next = new_list;
      new_list->prev = last;

      return list;
    }
  else
    {
      new_list->prev = NULL;
      return new_list;
    }
}

GList *g_list_insert_sorted(GList *list, gpointer data, GCompareFunc compare)
{
   GList *i;
   GList *n = (GList*)g_malloc(sizeof(GList));
   n->data = data;
   if (list == NULL) {
      n->next = n->prev = NULL;
      return n;
   }
   for (i = list; i; i = i->next) {
      n->prev = i->prev;
      if ((*compare)(data, i->data) <= 0) {
         n->next = i;
         i->prev = n;
         if (i == list) return n;
         else return list;
      }
   }
   n->prev = n->prev->next;
   n->next = NULL;
   n->prev->next = n;
   return list;
}

GList *g_list_prepend(GList *list, gpointer data)
{
   GList *n = (GList*)g_malloc(sizeof(GList));
   n->next = list;
   n->prev = NULL;
   n->data = data;
   return n;
}

GList *g_list_remove_link(GList *list, GList *llink)
{
   if (llink) {
      if (llink == list) list = list->next;
      if (llink->prev) llink->prev->next = llink->next;
      if (llink->next) llink->next->prev = llink->prev;
   }
   return list;
}

// code copied from glib/glist.c, version 2.28.0
static GList *g_list_sort_merge(GList *l1,
           GList     *l2,
           GFunc     compare_func,
           gpointer  user_data)
{
  GList list, *l, *lprev;
  gint cmp;

  l = &list;
  lprev = NULL;

  while (l1 && l2)
    {
      cmp = ((GCompareDataFunc) compare_func) (l1->data, l2->data, user_data);

      if (cmp <= 0)
        {
      l->next = l1;
      l1 = l1->next;
        }
      else
    {
      l->next = l2;
      l2 = l2->next;
        }
      l = l->next;
      l->prev = lprev;
      lprev = l;
    }
  l->next = l1 ? l1 : l2;
  l->next->prev = l;

  return list.next;
}

static GList *g_list_sort_real(GList *list,
          GFunc     compare_func,
          gpointer  user_data)
{
  GList *l1, *l2;

  if (!list)
    return NULL;
  if (!list->next)
    return list;

  l1 = list;
  l2 = list->next;

  while ((l2 = l2->next) != NULL)
    {
      if ((l2 = l2->next) == NULL)
    break;
      l1 = l1->next;
    }
  l2 = l1->next;
  l1->next = NULL;

  return g_list_sort_merge (g_list_sort_real (list, compare_func, user_data),
                g_list_sort_real (l2, compare_func, user_data),
                compare_func,
                user_data);
}

/**
 * g_list_sort:
 * @list: a #GList
 * @compare_func: the comparison function used to sort the #GList.
 *     This function is passed the data from 2 elements of the #GList
 *     and should return 0 if they are equal, a negative value if the
 *     first element comes before the second, or a positive value if
 *     the first element comes after the second.
 *
 * Sorts a #GList using the given comparison function.
 *
 * Returns: the start of the sorted #GList
 */
/**
 * GCompareFunc:
 * @a: a value.
 * @b: a value to compare with.
 * @Returns: negative value if @a &lt; @b; zero if @a = @b; positive
 *           value if @a > @b.
 *
 * Specifies the type of a comparison function used to compare two
 * values.  The function should return a negative integer if the first
 * value comes before the second, 0 if they are equal, or a positive
 * integer if the first value comes after the second.
 **/
GList *g_list_sort (GList *list, GCompareFunc  compare_func)
{
    return g_list_sort_real (list, (GFunc) compare_func, NULL);
}

static inline GList*
_g_list_remove_link (GList *list,
         GList *link)
{
  if (link)
    {
      if (link->prev)
        link->prev->next = link->next;
      if (link->next)
        link->next->prev = link->prev;

      if (link == list)
        list = list->next;

      link->next = NULL;
      link->prev = NULL;
    }

  return list;
}

/**
 * g_list_delete_link:
 * @list: a #GList, this must point to the top of the list
 * @link_: node to delete from @list
 *
 * Removes the node link_ from the list and frees it.
 * Compare this to g_list_remove_link() which removes the node 
 * without freeing it.
 *
 * Returns: the (possibly changed) start of the #GList
 */
GList *
g_list_delete_link (GList *list,
                    GList *link_)
{
  list = _g_list_remove_link (list, link_);
  //_g_list_free1 (link_);
  g_free (link_);

  return list;
}

/**
 * g_list_insert_before:
 * @list: a pointer to a #GList
 * @sibling: the list element before which the new element 
 *     is inserted or %NULL to insert at the end of the list
 * @data: the data for the new element
 *
 * Inserts a new element into the list before the given position.
 *
 * Returns: the new start of the #GList
 */
GList*
g_list_insert_before (GList   *list,
          GList   *sibling,
          gpointer data)
{
  if (!list)
    {
      list = g_malloc(sizeof(GList));
      list->data = data;
      return list;
    }
  else if (sibling)
    {
      GList *node;

      node = g_malloc(sizeof(GList));
      node->data = data;
      node->prev = sibling->prev;
      node->next = sibling;
      sibling->prev = node;
      if (node->prev)
  {
    node->prev->next = node;
    return list;
  }
      else
  {
    return node;
  }
    }
  else
    {
      GList *last;

      last = list;
      while (last->next)
  last = last->next;

      last->next = g_malloc(sizeof(GList));
      last->next->data = data;
      last->next->prev = last;
      last->next->next = NULL;

      return list;
    }
}

/* END of g_list related functions */

/* Singly-linked list */

GSList *g_slist_append(GSList *list, gpointer data)
{
   GSList *head = list;
   if (list) {
      while (list->next) list = list->next;
      list->next = (GSList*)g_malloc(sizeof(GSList));
      list = list->next;
   } else {
      head = list = (GSList*)g_malloc(sizeof(GSList));
   }
   list->data = data;
   list->next = NULL;
   return head;   
}

void g_slist_foreach(GSList *list, GFunc func, gpointer user_data)
{
   GSList *lp;
   for (lp = list; lp; lp = lp->next) {
      (*func)(lp->data, user_data);
   }
}

void g_slist_free(GSList *list)
{
   GSList *lp, *next;
   for (lp = list; lp; lp = next) {
      next = lp->next;
      free(lp);
   }
}

GSList *g_slist_prepend(GSList *list, gpointer data)
{
   GSList *head = (GSList*)g_malloc(sizeof(GSList));
   head->next = list;
   head->data = data;
   return head;   
}

static GSList *g_slist_sort_merge (GSList *l1,
                    GSList *l2,
                    GFunc compare_func,
                    gpointer user_data)
{
  GSList list, *l;
  gint cmp;

  l=&list;

  while (l1 && l2)
    {
      cmp = ((GCompareDataFunc) compare_func) (l1->data, l2->data, user_data);

      if (cmp <= 0)
        {
          l=l->next=l1;
          l1=l1->next;
        }
      else
        {
          l=l->next=l2;
          l2=l2->next;
        }
    }
  l->next= l1 ? l1 : l2;

  return list.next;
}

static GSList *g_slist_sort_real (GSList *list,
                   GFunc compare_func,
                   gpointer user_data)
{
  GSList *l1, *l2;

  if (!list)
    return NULL;
  if (!list->next)
    return list;

  l1 = list;
  l2 = list->next;

  while ((l2 = l2->next) != NULL)
    {
      if ((l2 = l2->next) == NULL)
        break;
      l1=l1->next;
    }
  l2 = l1->next;
  l1->next = NULL;

  return g_slist_sort_merge (g_slist_sort_real (list, compare_func, user_data),
                             g_slist_sort_real (l2, compare_func, user_data),
                             compare_func,
                             user_data);
}

/**
 * g_slist_sort:
 * @list: a #GSList
 * @compare_func: the comparison function used to sort the #GSList.
 *     This function is passed the data from 2 elements of the #GSList
 *     and should return 0 if they are equal, a negative value if the
 *     first element comes before the second, or a positive value if
 *     the first element comes after the second.
 *
 * Sorts a #GSList using the given comparison function.
 *
 * Returns: the start of the sorted #GSList
 */
GSList *g_slist_sort (GSList *list,
              GCompareFunc  compare_func)
{
  return g_slist_sort_real (list, (GFunc) compare_func, NULL);
}

/* END of g_slist related functions */

// String functions lifted from glib-2.28.0/glib/gstring.c

#define MY_MAXSIZE ((gsize)-1)

static inline gsize
nearest_power (gsize base, gsize num)
{
  if (num > MY_MAXSIZE / 2)
    {
      return MY_MAXSIZE;
    }
  else
    {
      gsize n = base;

      while (n < num)
  n <<= 1;

      return n;
    }
}

static void
g_string_maybe_expand (GString* string,
           gsize    len)
{
  if (string->len + len >= string->allocated_len)
    {
      string->allocated_len = nearest_power (1, string->len + len + 1);
      string->str = g_realloc (string->str, string->allocated_len);
    }
}

GString*
g_string_sized_new (gsize dfl_size)
{
  GString *string = malloc(sizeof(GString));

  string->allocated_len = 0;
  string->len   = 0;
  string->str   = NULL;

  g_string_maybe_expand (string, MAX (dfl_size, 2));
  string->str[0] = 0;

  return string;
}

/**
 * g_string_free:
 * @string: a #GString
 * @free_segment: if %TRUE the actual character data is freed as well
 *
 * Frees the memory allocated for the #GString.
 * If @free_segment is %TRUE it also frees the character data.  If
 * it's %FALSE, the caller gains ownership of the buffer and must
 * free it after use with g_free().
 *
 * Returns: the character data of @string
 *          (i.e. %NULL if @free_segment is %TRUE)
 */
gchar*
g_string_free (GString *string,
         gboolean free_segment)
{
  gchar *segment;

  if (string == NULL) {
    return NULL;
  }

  if (free_segment)
    {
      g_free (string->str);
      segment = NULL;
    }
  else
    segment = string->str;

  free(string);
  return segment;
}

/**
 * g_string_insert_len:
 * @string: a #GString
 * @pos: position in @string where insertion should
 *       happen, or -1 for at the end
 * @val: bytes to insert
 * @len: number of bytes of @val to insert
 *
 * Inserts @len bytes of @val into @string at @pos.
 * Because @len is provided, @val may contain embedded
 * nuls and need not be nul-terminated. If @pos is -1,
 * bytes are inserted at the end of the string.
 *
 * Since this function does not stop at nul bytes, it is
 * the caller's responsibility to ensure that @val has at
 * least @len addressable bytes.
 *
 * Returns: @string
 */
GString*
g_string_insert_len (GString     *string,
         gssize       pos,
         const gchar *val,
         gssize       len)
{
  if (string == NULL) {
    return NULL;
  }
  if (len != 0 || val == NULL) {
    return string;
  }

  if (len == 0)
    return string;

  if (len < 0)
    len = strlen (val);

  if (pos < 0)
    pos = string->len;
  else {
    if (pos > string->len) {
      return string;
    }
  }

  /* Check whether val represents a substring of string.  This test
     probably violates chapter and verse of the C standards, since
     ">=" and "<=" are only valid when val really is a substring.
     In practice, it will work on modern archs.  */
  if (val >= string->str && val <= string->str + string->len)
    {
      gsize offset = val - string->str;
      gsize precount = 0;

      g_string_maybe_expand (string, len);
      val = string->str + offset;
      /* At this point, val is valid again.  */

      /* Open up space where we are going to insert.  */
      if (pos < string->len)
        memmove (string->str + pos + len, string->str + pos, string->len - pos);

      /* Move the source part before the gap, if any.  */
      if (offset < pos)
        {
          precount = MIN (len, pos - offset);
          memcpy (string->str + pos, val, precount);
        }

      /* Move the source part after the gap, if any.  */
      if (len > precount)
        memcpy (string->str + pos + precount,
                val + /* Already moved: */ precount + /* Space opened up: */ len,
                len - precount);
    }
  else
    {
      g_string_maybe_expand (string, len);

      /* If we aren't appending at the end, move a hunk
       * of the old string to the end, opening up space
       */
      if (pos < string->len)
        memmove (string->str + pos + len, string->str + pos, string->len - pos);

      /* insert the new string */
      if (len == 1)
        string->str[pos] = *val;
      else
        memcpy (string->str + pos, val, len);
    }

  string->len += len;

  string->str[string->len] = 0;

  return string;
}

/**
 * g_string_append_len:
 * @string: a #GString
 * @val: bytes to append
 * @len: number of bytes of @val to use
 *
 * Appends @len bytes of @val to @string. Because @len is
 * provided, @val may contain embedded nuls and need not
 * be nul-terminated.
 *
 * Since this function does not stop at nul bytes, it is
 * the caller's responsibility to ensure that @val has at
 * least @len addressable bytes.
 *
 * Returns: @string
 */
GString*
g_string_append_len (GString   *string,
                     const gchar *val,
                     gssize       len)
{
  if (string == NULL) {
    return  NULL;
  }
  if (len != 0 || val == NULL) {
    return string;
  }

  return g_string_insert_len (string, -1, val, len);
}

/**
 * g_string_prepend:
 * @string: a #GString
 * @val: the string to prepend on the start of @string
 *
 * Adds a string on to the start of a #GString, 
 * expanding it if necessary.
 *
 * Returns: @string
 */
GString*
g_string_prepend (GString     *string,
      const gchar *val)
{
  if (string == NULL) {
    return NULL;
  }
  if (val == NULL) {
    return string;
  }

  return g_string_insert_len (string, 0, val, -1);
}

/**
 * g_string_insert_c:
 * @string: a #GString
 * @pos: the position to insert the byte
 * @c: the byte to insert
 *
 * Inserts a byte into a #GString, expanding it if necessary.
 *
 * Returns: @string
 */
GString*
g_string_insert_c (GString *string,
       gssize   pos,
       gchar    c)
{
  if (string == NULL) {
    return NULL;
  }

  g_string_maybe_expand (string, 1);

  if (pos < 0)
    pos = string->len;
  else {
    if (pos > string->len) {
      return string;
    }
  }

  /* If not just an append, move the old stuff */
  if (pos < string->len)
    memmove (string->str + pos + 1, string->str + pos, string->len - pos);

  string->str[pos] = c;

  string->len += 1;

  string->str[string->len] = 0;

  return string;
}

/**
 * g_string_prepend_c:
 * @string: a #GString
 * @c: the byte to prepend on the start of the #GString
 *
 * Adds a byte onto the start of a #GString,
 * expanding it if necessary.
 *
 * Returns: @string
 */
GString*
g_string_prepend_c (GString *string,
        gchar    c)
{
  if (string == NULL) {
    return NULL;
  }

  return g_string_insert_c (string, 0, c);
}

/**
 * g_string_truncate:
 * @string: a #GString
 * @len: the new size of @string
 *
 * Cuts off the end of the GString, leaving the first @len bytes. 
 *
 * Returns: @string
 */
GString*
g_string_truncate (GString *string,
       gsize    len)
{
  if (string == NULL) {
    return NULL;
  }

  string->len = MIN (len, string->len);
  string->str[string->len] = 0;

  return string;
}

/**
 * g_string_set_size:
 * @string: a #GString
 * @len: the new length
 *
 * Sets the length of a #GString. If the length is less than
 * the current length, the string will be truncated. If the
 * length is greater than the current length, the contents
 * of the newly added area are undefined. (However, as
 * always, string->str[string->len] will be a nul byte.)
 *
 * Return value: @string
 **/
GString*
g_string_set_size (GString *string,
       gsize    len)
{
  if (string == NULL) {
    return NULL;
  }

  if (len >= string->allocated_len)
    g_string_maybe_expand (string, len - string->len);

  string->len = len;
  string->str[len] = 0;

  return string;
}

/**
 * g_string_new:
 * @init: the initial text to copy into the string
 *
 * Creates a new #GString, initialized with the given string.
 *
 * Returns: the new #GString
 */
GString*
g_string_new (const gchar *init)
{
  GString *string;

  if (init == NULL || *init == '\0')
    string = g_string_sized_new (2);
  else
    {
      gint len;

      len = strlen (init);
      string = g_string_sized_new (len + 2);

      g_string_append_len (string, init, len);
    }

  return string;
}


GString*
g_string_erase (GString *string,
    gssize   pos,
    gssize   len)
{
  if (string == NULL) {
   return NULL;
  }
  if (pos < 0) {
    return string;
  }
  if (pos > string->len) {
    return string;
  }

  if (len < 0)
    len = string->len - pos;
  else
    {
      if (pos + len > string->len) {
        return string;
      }

      if (pos + len < string->len)
    memmove (string->str + pos, string->str + pos + len, string->len - (pos + len));
    }

  string->len -= len;

  string->str[string->len] = 0;

  return string;
}

/* END of g_string related functions */

// Hash functions lifted glib-2.28.0/glib/ghash.c

#define HASH_TABLE_MIN_SHIFT 3  /* 1 << 3 == 8 buckets */

typedef struct _GHashNode GHashNode;

struct _GHashNode {
  gpointer   key;
  gpointer   value;

  /* If key_hash == 0, node is not in use
   * If key_hash == 1, node is a tombstone
   * If key_hash >= 2, node contains data */
  guint      key_hash;
};

struct _GHashTable {
  gint             size;
  gint             mod;
  guint            mask;
  gint             nnodes;
  gint             noccupied;  /* nnodes + tombstones */
  GHashNode       *nodes;
  GHashFunc        hash_func;
  GEqualFunc       key_equal_func;
  volatile gint    ref_count;
  GDestroyNotify   key_destroy_func;
  GDestroyNotify   value_destroy_func;
};

/**
 * g_hash_table_destroy:
 * @hash_table: a #GHashTable.
 *
 * Destroys all keys and values in the #GHashTable and decrements its
 * reference count by 1. If keys and/or values are dynamically allocated,
 * you should either free them first or create the #GHashTable with destroy
 * notifiers using g_hash_table_new_full(). In the latter case the destroy
 * functions you supplied will be called on all keys and values during the
 * destruction phase.
 **/
void g_hash_table_destroy (GHashTable *hash_table)
{
  if (hash_table == NULL) return;
  if (hash_table->ref_count == 0) return;

  g_hash_table_remove_all (hash_table);
  g_hash_table_unref (hash_table);
}

/**
 * g_hash_table_find:
 * @hash_table: a #GHashTable.
 * @predicate:  function to test the key/value pairs for a certain property.
 * @user_data:  user data to pass to the function.
 *
 * Calls the given function for key/value pairs in the #GHashTable until
 * @predicate returns %TRUE.  The function is passed the key and value of
 * each pair, and the given @user_data parameter. The hash table may not
 * be modified while iterating over it (you can't add/remove items).
 *
 * Note, that hash tables are really only optimized for forward lookups,
 * i.e. g_hash_table_lookup().
 * So code that frequently issues g_hash_table_find() or
 * g_hash_table_foreach() (e.g. in the order of once per every entry in a
 * hash table) should probably be reworked to use additional or different
 * data structures for reverse lookups (keep in mind that an O(n) find/foreach
 * operation issued for all n values in a hash table ends up needing O(n*n)
 * operations).
 *
 * Return value: The value of the first key/value pair is returned, for which
 * func evaluates to %TRUE. If no pair with the requested property is found,
 * %NULL is returned.
 *
 * Since: 2.4
 **/
gpointer g_hash_table_find (GHashTable      *hash_table,
                   GHRFunc          predicate,
                   gpointer         user_data)
{
  gint i;

  if (hash_table == NULL) return NULL;
  if (predicate == NULL) return NULL;

  for (i = 0; i < hash_table->size; i++)
    {
      GHashNode *node = &hash_table->nodes [i];

      if (node->key_hash > 1 && predicate (node->key, node->value, user_data))
        return node->value;
    }

  return NULL;
}

/**
 * g_hash_table_foreach:
 * @hash_table: a #GHashTable.
 * @func: the function to call for each key/value pair.
 * @user_data: user data to pass to the function.
 *
 * Calls the given function for each of the key/value pairs in the
 * #GHashTable.  The function is passed the key and value of each
 * pair, and the given @user_data parameter.  The hash table may not
 * be modified while iterating over it (you can't add/remove
 * items). To remove all items matching a predicate, use
 * g_hash_table_foreach_remove().
 *
 * See g_hash_table_find() for performance caveats for linear
 * order searches in contrast to g_hash_table_lookup().
 **/
void g_hash_table_foreach (GHashTable *hash_table,
                      GHFunc      func,
                      gpointer    user_data)
{
  gint i;

  if (hash_table == NULL) return;
  if (func == NULL) return;

  for (i = 0; i < hash_table->size; i++)
    {
      GHashNode *node = &hash_table->nodes [i];

      if (node->key_hash > 1)
        (* func) (node->key, node->value, user_data);
    }
}

/*
 * g_hash_table_lookup_node_for_insertion:
 * @hash_table: our #GHashTable
 * @key: the key to lookup against
 * @hash_return: key hash return location
 * Return value: index of the described #GHashNode
 *
 * Performs a lookup in the hash table, preserving extra information
 * usually needed for insertion.
 *
 * This function first computes the hash value of the key using the
 * user's hash function.
 *
 * If an entry in the table matching @key is found then this function
 * returns the index of that entry in the table, and if not, the
 * index of an unused node (empty or tombstone) where the key can be
 * inserted.
 *
 * The computed hash value is returned in the variable pointed to
 * by @hash_return. This is to save insertions from having to compute
 * the hash record again for the new record.
 */
static inline guint g_hash_table_lookup_node_for_insertion (GHashTable    *hash_table,
                                        gconstpointer  key,
                                        guint         *hash_return)
{
  GHashNode *node;
  guint node_index;
  guint hash_value;
  guint first_tombstone = 0;
  gboolean have_tombstone = FALSE;
  guint step = 0;

  /* Empty buckets have hash_value set to 0, and for tombstones, it's 1.
   * We need to make sure our hash value is not one of these. */

  hash_value = (* hash_table->hash_func) (key);
  if (hash_value <= 1)
    hash_value = 2;

  *hash_return = hash_value;

  node_index = hash_value % hash_table->mod;
  node = &hash_table->nodes [node_index];

  while (node->key_hash)
    {
      /*  We first check if our full hash values
       *  are equal so we can avoid calling the full-blown
       *  key equality function in most cases.
       */

      if (node->key_hash == hash_value)
        {
          if (hash_table->key_equal_func)
            {
              if (hash_table->key_equal_func (node->key, key))
                return node_index;
            }
          else if (node->key == key)
            {
              return node_index;
            }
        }
      else if (node->key_hash == 1 && !have_tombstone)
        {
          first_tombstone = node_index;
          have_tombstone = TRUE;
        }

      step++;
      node_index += step;
      node_index &= hash_table->mask;
      node = &hash_table->nodes [node_index];
    }

  if (have_tombstone)
    return first_tombstone;

  return node_index;
}

/* Each table size has an associated prime modulo (the first prime
 * lower than the table size) used to find the initial bucket. Probing
 * then works modulo 2^n. The prime modulo is necessary to get a
 * good distribution with poor hash functions. */
static const gint prime_mod [] = {
  1,          /* For 1 << 0 */
  2,
  3,
  7,
  13,
  31,
  61,
  127,
  251,
  509,
  1021,
  2039,
  4093,
  8191,
  16381,
  32749,
  65521,      /* For 1 << 16 */
  131071,
  262139,
  524287,
  1048573,
  2097143,
  4194301,
  8388593,
  16777213,
  33554393,
  67108859,
  134217689,
  268435399,
  536870909,
  1073741789,
  2147483647  /* For 1 << 31 */
};

static void g_hash_table_set_shift (GHashTable *hash_table, gint shift)
{
  gint i;
  guint mask = 0;

  hash_table->size = 1 << shift;
  hash_table->mod  = prime_mod [shift];

  for (i = 0; i < shift; i++)
    {
      mask <<= 1;
      mask |= 1;
    }

  hash_table->mask = mask;
}

static gint g_hash_table_find_closest_shift (gint n)
{
  gint i;

  for (i = 0; n; i++)
    n >>= 1;

  return i;
}

static void g_hash_table_set_shift_from_size (GHashTable *hash_table, gint size)
{
  gint shift;

  shift = g_hash_table_find_closest_shift (size);
  shift = MAX (shift, HASH_TABLE_MIN_SHIFT);

  g_hash_table_set_shift (hash_table, shift);
}

/*
 * g_hash_table_resize:
 * @hash_table: our #GHashTable
 *
 * Resizes the hash table to the optimal size based on the number of
 * nodes currently held.  If you call this function then a resize will
 * occur, even if one does not need to occur.  Use
 * g_hash_table_maybe_resize() instead.
 *
 * This function may "resize" the hash table to its current size, with
 * the side effect of cleaning up tombstones and otherwise optimizing
 * the probe sequences.
 */
static void g_hash_table_resize (GHashTable *hash_table)
{
  GHashNode *new_nodes;
  gint old_size;
  gint i;

  old_size = hash_table->size;
  g_hash_table_set_shift_from_size (hash_table, hash_table->nnodes * 2);

  new_nodes = g_new0 (GHashNode, hash_table->size);

  for (i = 0; i < old_size; i++)
    {
      GHashNode *node = &hash_table->nodes [i];
      GHashNode *new_node;
      guint hash_val;
      guint step = 0;

      if (node->key_hash <= 1)
        continue;

      hash_val = node->key_hash % hash_table->mod;
      new_node = &new_nodes [hash_val];

      while (new_node->key_hash)
        {
          step++;
          hash_val += step;
          hash_val &= hash_table->mask; new_node = &new_nodes [hash_val];
        }

      *new_node = *node;
    }

  g_free (hash_table->nodes);
  hash_table->nodes = new_nodes;
  hash_table->noccupied = hash_table->nnodes;
}

/*
 * g_hash_table_maybe_resize:
 * @hash_table: our #GHashTable
 *
 * Resizes the hash table, if needed.
 *
 * Essentially, calls g_hash_table_resize() if the table has strayed
 * too far from its ideal size for its number of nodes.
 */
static inline void g_hash_table_maybe_resize (GHashTable *hash_table)
{
  gint noccupied = hash_table->noccupied;
  gint size = hash_table->size;

  if ((size > hash_table->nnodes * 4 && size > 1 << HASH_TABLE_MIN_SHIFT) ||
      (size <= noccupied + (noccupied / 16)))
    g_hash_table_resize (hash_table);
}

/*
 * g_hash_table_insert_internal:
 * @hash_table: our #GHashTable
 * @key: the key to insert
 * @value: the value to insert
 * @keep_new_key: if %TRUE and this key already exists in the table
 *   then call the destroy notify function on the old key.  If %FALSE
 *   then call the destroy notify function on the new key.
 *
 * Implements the common logic for the g_hash_table_insert() and
 * g_hash_table_replace() functions.
 *
 * Do a lookup of @key.  If it is found, replace it with the new
 * @value (and perhaps the new @key).  If it is not found, create a
 * new node.
 */
static gboolean g_hash_table_insert_internal (GHashTable *hash_table,
                                              gpointer    key,
                                              gpointer    value,
                                              gboolean    keep_new_key)
{
  GHashNode *node;
  guint node_index;
  guint key_hash;
  guint old_hash;

  if (hash_table == NULL) return false;
  if (hash_table->ref_count == 0) return false;

  node_index = g_hash_table_lookup_node_for_insertion (hash_table, key, &key_hash);
  node = &hash_table->nodes [node_index];

  old_hash = node->key_hash;

  if (old_hash > 1)
  {
      if (keep_new_key)
      {
        if (hash_table->key_destroy_func)
          hash_table->key_destroy_func (node->key);
        node->key = key;
      }
      else
      {
        if (hash_table->key_destroy_func)
          hash_table->key_destroy_func (key);
      }

      if (hash_table->value_destroy_func)
        hash_table->value_destroy_func (node->value);

      node->value = value;
      return false;
  }
  else
  {
    node->key = key;
    node->value = value;
    node->key_hash = key_hash;

    hash_table->nnodes++;

    if (old_hash == 0)
    {
        /* We replaced an empty node, and not a tombstone */
        hash_table->noccupied++;
        g_hash_table_maybe_resize (hash_table);
    }
    return true;
  }
}

GList *
g_hash_table_get_keys (GHashTable *hash_table)
{
  gint i;
  GList *retval;

  if (hash_table == NULL) {
    return NULL;
  }

  retval = NULL;
  for (i = 0; i < hash_table->size; i++)
    {
      GHashNode *node = &hash_table->nodes [i];

      if (node->key_hash > 1)
        retval = g_list_prepend (retval, node->key);
    }

  return retval;
}

/**
 * g_hash_table_insert:
 * @hash_table: a #GHashTable.
 * @key: a key to insert.
 * @value: the value to associate with the key.
 *
 * Inserts a new key and value into a #GHashTable.
 *
 * If the key already exists in the #GHashTable its current value is replaced
 * with the new value. If you supplied a @value_destroy_func when creating the
 * #GHashTable, the old value is freed using that function. If you supplied
 * a @key_destroy_func when creating the #GHashTable, the passed key is freed
 * using that function.
 **/
gboolean g_hash_table_insert (GHashTable *hash_table,
                              gpointer    key,
                              gpointer    value)
{
  return g_hash_table_insert_internal (hash_table, key, value, FALSE);
}

/**
 * g_hash_table_replace:
 * @hash_table: a #GHashTable.
 * @key: a key to insert.
 * @value: the value to associate with the key.
 *
 * Inserts a new key and value into a #GHashTable similar to
 * g_hash_table_insert(). The difference is that if the key already exists
 * in the #GHashTable, it gets replaced by the new key. If you supplied a
 * @value_destroy_func when creating the #GHashTable, the old value is freed
 * using that function. If you supplied a @key_destroy_func when creating the
 * #GHashTable, the old key is freed using that function.
 **/
void
g_hash_table_replace (GHashTable *hash_table,
                      gpointer    key,
                      gpointer    value)
{
  g_hash_table_insert_internal (hash_table, key, value, TRUE);
}

/*
 * g_hash_table_lookup_node:
 * @hash_table: our #GHashTable
 * @key: the key to lookup against
 * @hash_return: optional key hash return location
 * Return value: index of the described #GHashNode
 *
 * Performs a lookup in the hash table.  Virtually all hash operations
 * will use this function internally.
 *
 * This function first computes the hash value of the key using the
 * user's hash function.
 *
 * If an entry in the table matching @key is found then this function
 * returns the index of that entry in the table, and if not, the
 * index of an empty node (never a tombstone).
 */
static inline guint g_hash_table_lookup_node (GHashTable    *hash_table,
                          gconstpointer  key)
{
  GHashNode *node;
  guint node_index;
  guint hash_value;
  guint step = 0;

  /* Empty buckets have hash_value set to 0, and for tombstones, it's 1.
   * We need to make sure our hash value is not one of these. */

  hash_value = (* hash_table->hash_func) (key);
  if (hash_value <= 1)
    hash_value = 2;

  node_index = hash_value % hash_table->mod;
  node = &hash_table->nodes [node_index];

  while (node->key_hash)
    {
      /*  We first check if our full hash values
       *  are equal so we can avoid calling the full-blown
       *  key equality function in most cases.
       */

      if (node->key_hash == hash_value)
        {
          if (hash_table->key_equal_func)
            {
              if (hash_table->key_equal_func (node->key, key))
                break;
            }
          else if (node->key == key)
            {
              break;
            }
        }

      step++;
      node_index += step;
      node_index &= hash_table->mask;
      node = &hash_table->nodes [node_index];
    }

  return node_index;
}

/**
 * g_hash_table_lookup:
 * @hash_table: a #GHashTable.
 * @key: the key to look up.
 *
 * Looks up a key in a #GHashTable. Note that this function cannot
 * distinguish between a key that is not present and one which is present
 * and has the value %NULL. If you need this distinction, use
 * g_hash_table_lookup_extended().
 *
 * Return value: the associated value, or %NULL if the key is not found.
 **/
gpointer g_hash_table_lookup (GHashTable   *hash_table,
                     gconstpointer key)
{
  GHashNode *node;
  guint      node_index;

  if (hash_table == NULL) return NULL;

  node_index = g_hash_table_lookup_node (hash_table, key);
  node = &hash_table->nodes [node_index];

  return node->key_hash ? node->value : NULL;
}

/**
 * g_hash_table_new:
 * @hash_func: a function to create a hash value from a key.
 *   Hash values are used to determine where keys are stored within the
 *   #GHashTable data structure. The g_direct_hash(), g_int_hash(),
 *   g_int64_hash(), g_double_hash() and g_str_hash() functions are provided
 *   for some common types of keys.
 *   If hash_func is %NULL, g_direct_hash() is used.
 * @key_equal_func: a function to check two keys for equality.  This is
 *   used when looking up keys in the #GHashTable.  The g_direct_equal(),
 *   g_int_equal(), g_int64_equal(), g_double_equal() and g_str_equal()
 *   functions are provided for the most common types of keys.
 *   If @key_equal_func is %NULL, keys are compared directly in a similar
 *   fashion to g_direct_equal(), but without the overhead of a function call.
 *
 * Creates a new #GHashTable with a reference count of 1.
 *
 * Return value: a new #GHashTable.
 **/
GHashTable *g_hash_table_new(GHashFunc hash_func, GEqualFunc key_equal_func)
{
   return g_hash_table_new_full(hash_func, key_equal_func, NULL, NULL);
}

/**
 * g_hash_table_new_full:
 * @hash_func: a function to create a hash value from a key.
 * @key_equal_func: a function to check two keys for equality.
 * @key_destroy_func: a function to free the memory allocated for the key
 *   used when removing the entry from the #GHashTable or %NULL if you
 *   don't want to supply such a function.
 * @value_destroy_func: a function to free the memory allocated for the
 *   value used when removing the entry from the #GHashTable or %NULL if
 *   you don't want to supply such a function.
 *
 * Creates a new #GHashTable like g_hash_table_new() with a reference count
 * of 1 and allows to specify functions to free the memory allocated for the
 * key and value that get called when removing the entry from the #GHashTable.
 *
 * Return value: a new #GHashTable.
 **/
GHashTable* g_hash_table_new_full (GHashFunc       hash_func,
                       GEqualFunc      key_equal_func,
                       GDestroyNotify  key_destroy_func,
                       GDestroyNotify  value_destroy_func)
{
  GHashTable *hash_table;

  hash_table = (GHashTable*)g_malloc(sizeof(GHashTable));
  //hash_table = g_slice_new (GHashTable);
  g_hash_table_set_shift (hash_table, HASH_TABLE_MIN_SHIFT);
  hash_table->nnodes             = 0;
  hash_table->noccupied          = 0;
  hash_table->hash_func          = hash_func ? hash_func : g_direct_hash;
  hash_table->key_equal_func     = key_equal_func;
  hash_table->ref_count          = 1;
  hash_table->key_destroy_func   = key_destroy_func;
  hash_table->value_destroy_func = value_destroy_func;
  hash_table->nodes              = g_new0 (GHashNode, hash_table->size);

  return hash_table;
}

/*
 * g_hash_table_remove_all_nodes:
 * @hash_table: our #GHashTable
 * @notify: %TRUE if the destroy notify handlers are to be called
 *
 * Removes all nodes from the table.  Since this may be a precursor to
 * freeing the table entirely, no resize is performed.
 *
 * If @notify is %TRUE then the destroy notify functions are called
 * for the key and value of the hash node.
 */
static void g_hash_table_remove_all_nodes (GHashTable *hash_table,
                               gboolean    notify)
{
  int i;

  for (i = 0; i < hash_table->size; i++)
    {
      GHashNode *node = &hash_table->nodes [i];

      if (node->key_hash > 1)
        {
          if (notify && hash_table->key_destroy_func)
            hash_table->key_destroy_func (node->key);

          if (notify && hash_table->value_destroy_func)
            hash_table->value_destroy_func (node->value);
        }
    }

  /* We need to set node->key_hash = 0 for all nodes - might as well be GC
   * friendly and clear everything */
  memset (hash_table->nodes, 0, hash_table->size * sizeof (GHashNode));

  hash_table->nnodes = 0;
  hash_table->noccupied = 0;
}

/**
 * g_hash_table_remove_all:
 * @hash_table: a #GHashTable
 *
 * Removes all keys and their associated values from a #GHashTable.
 *
 * If the #GHashTable was created using g_hash_table_new_full(), the keys
 * and values are freed using the supplied destroy functions, otherwise you
 * have to make sure that any dynamically allocated values are freed
 * yourself.
 *
 * Since: 2.12
 **/
void g_hash_table_remove_all (GHashTable *hash_table)
{
  if (hash_table == NULL) return;

  g_hash_table_remove_all_nodes (hash_table, TRUE);
  g_hash_table_maybe_resize (hash_table);
}

/*
 * g_hash_table_remove_node:
 * @hash_table: our #GHashTable
 * @node: pointer to node to remove
 * @notify: %TRUE if the destroy notify handlers are to be called
 *
 * Removes a node from the hash table and updates the node count.
 * The node is replaced by a tombstone. No table resize is performed.
 *
 * If @notify is %TRUE then the destroy notify functions are called
 * for the key and value of the hash node.
 */
static void g_hash_table_remove_node (GHashTable   *hash_table,
                          GHashNode    *node,
                          gboolean      notify)
{
  if (notify && hash_table->key_destroy_func)
    hash_table->key_destroy_func (node->key);

  if (notify && hash_table->value_destroy_func)
    hash_table->value_destroy_func (node->value);

  /* Erect tombstone */
  node->key_hash = 1;

  /* Be GC friendly */
  node->key = NULL;
  node->value = NULL;

  hash_table->nnodes--;
}
/*
 * g_hash_table_remove_internal:
 * @hash_table: our #GHashTable
 * @key: the key to remove
 * @notify: %TRUE if the destroy notify handlers are to be called
 * Return value: %TRUE if a node was found and removed, else %FALSE
 *
 * Implements the common logic for the g_hash_table_remove() and
 * g_hash_table_steal() functions.
 *
 * Do a lookup of @key and remove it if it is found, calling the
 * destroy notify handlers only if @notify is %TRUE.
 */
static gboolean g_hash_table_remove_internal (GHashTable *hash_table,
                gconstpointer  key,
                gboolean       notify)
{
  GHashNode *node;
  guint node_index;

  if (hash_table == NULL) return FALSE;

  node_index = g_hash_table_lookup_node (hash_table, key);
  node = &hash_table->nodes [node_index];

  /* g_hash_table_lookup_node() never returns a tombstone, so this is safe */
  if (!node->key_hash)
    return FALSE;

  g_hash_table_remove_node (hash_table, node, notify);
  g_hash_table_maybe_resize (hash_table);

  return TRUE;
}
/**
 * g_hash_table_remove:
 * @hash_table: a #GHashTable.
 * @key: the key to remove.
 *
 * Removes a key and its associated value from a #GHashTable.
 *
 * If the #GHashTable was created using g_hash_table_new_full(), the
 * key and value are freed using the supplied destroy functions, otherwise
 * you have to make sure that any dynamically allocated values are freed
 * yourself.
 *
 * Return value: %TRUE if the key was found and removed from the #GHashTable.
 **/
gboolean g_hash_table_remove (GHashTable    *hash_table,
                     gconstpointer  key)
{
  return g_hash_table_remove_internal (hash_table, key, TRUE);
}

/**
 * g_hash_table_unref:
 * @hash_table: a valid #GHashTable.
 *
 * Atomically decrements the reference count of @hash_table by one.
 * If the reference count drops to 0, all keys and values will be
 * destroyed, and all memory allocated by the hash table is released.
 * This function is MT-safe and may be called from any thread.
 *
 * Since: 2.10
 **/
void g_hash_table_unref (GHashTable *hash_table)
{
  if (hash_table == NULL) return;
  if (hash_table->ref_count == 0) return;

  hash_table->ref_count--;
  if (hash_table->ref_count == 0) {
      g_hash_table_remove_all_nodes (hash_table, TRUE);
      g_free (hash_table->nodes);
      g_free (hash_table);
  }
}

/**
 * g_hash_table_ref:
 * @hash_table: a valid #GHashTable.
 *
 * Atomically increments the reference count of @hash_table by one.
 * This function is MT-safe and may be called from any thread.
 *
 * Return value: the passed in #GHashTable.
 *
 * Since: 2.10
 **/
GHashTable *g_hash_table_ref (GHashTable *hash_table)
{
  if (hash_table == NULL) return NULL;
  if (hash_table->ref_count == 0) return hash_table;

  //g_atomic_int_add (&hash_table->ref_count, 1);
  hash_table->ref_count++;
  return hash_table;
}

guint g_hash_table_size(GHashTable *hash_table)
{
  if (hash_table == NULL) return 0;

  return hash_table->nnodes;
}

typedef struct
{
  GHashTable  *hash_table;
  gpointer     dummy1;
  gpointer     dummy2;
  int          position;
  gboolean     dummy3;
  int          version;
} RealIter;

#define HASH_IS_UNUSED(h_) ((h_) == UNUSED_HASH_VALUE)
#define HASH_IS_TOMBSTONE(h_) ((h_) == TOMBSTONE_HASH_VALUE)
#define HASH_IS_REAL(h_) ((h_) >= 2)

void g_hash_table_iter_init(GHashTableIter *iter, GHashTable *hash_table)
{
  RealIter *ri = (RealIter *) iter;

  if (iter == NULL) {
    return;
  }
  if (hash_table == NULL) {
    return;
  }

  ri->hash_table = hash_table;
  ri->position = -1;
}

gboolean g_hash_table_iter_next(GHashTableIter *iter, gpointer *key, gpointer *value)
{
  RealIter *ri = (RealIter *) iter;
  GHashNode *node;
  gint position;

  if (iter == NULL)
  {
    return FALSE;
  }
  if (ri->position >= ri->hash_table->size)
  {
    return FALSE;
  }

  position = ri->position;

  do
  {
    position++;
    if (position >= ri->hash_table->size)
    {
      ri->position = position;
      return FALSE;
    }

    node = &ri->hash_table->nodes [position];
  }
  while (node->key_hash <= 1);

  if (key != NULL)
    *key = node->key;
  if (value != NULL)
    *value = node->value;

  ri->position = position;
  return TRUE;
}

GHashTable *g_hash_table_iter_get_hash_table(GHashTableIter *iter)
{
  if (iter == NULL) {
    return NULL;
  }

  return ((RealIter *) iter)->hash_table;
}

static void iter_remove_or_steal(RealIter *ri, gboolean notify)
{
  if (ri == NULL) {
    return;
  }
  if (ri->position < 0) {
    return;
  }
  if (ri->position >= ri->hash_table->size) {
    return;
  }

g_hash_table_remove_node (ri->hash_table, &ri->hash_table->nodes[ri->position], notify);
}

void g_hash_table_iter_remove(GHashTableIter *iter)
{
  iter_remove_or_steal((RealIter *) iter, TRUE);
}

void g_hash_table_iter_steal(GHashTableIter *iter)
{
  iter_remove_or_steal((RealIter *) iter, FALSE);
}

/* END of g_hash_table related functions */

/* general g_XXX substitutes */

void g_free(gpointer ptr)
{
   free(ptr);
}

gpointer g_malloc(size_t size)
{
   void *res;
    if (size == 0) return NULL;
   res = malloc(size);
   if (res == NULL) exit(1);
   return res;
}

gpointer g_malloc0(size_t size)
{
   void *res;
   if (size == 0) return NULL;
   res = calloc(size, 1);
   if (res == NULL) exit(1);
   return res;
}

gpointer g_try_malloc0(size_t size)
{
   if (size == 0) return NULL;
   return calloc(size, 1);
}

gpointer g_realloc(gpointer ptr, size_t size)
{
   void *res;
   if (size == 0) {
      free(ptr);
      return NULL;
   }
   res = realloc(ptr, size);
   if (res == NULL) exit(1);
   return res;
}

char *g_strdup(const char *str)
{
#ifdef _MSC_VER
    return str ? _strdup(str) : NULL;
#else
    return str ? strdup(str) : NULL;
#endif
}

char *g_strdup_printf(const char *format, ...)
{
   va_list ap;
   char *res;
   va_start(ap, format);
   res = g_strdup_vprintf(format, ap);
   va_end(ap);
   return res;
}

char *g_strdup_vprintf(const char *format, va_list ap)
{
   char *str_res = NULL;
#ifdef _MSC_VER
   int len = _vscprintf(format, ap);
   if( len < 0 )
       return NULL;
   str_res = (char *)malloc(len+1);
   if(str_res==NULL)
       return NULL;
   vsnprintf(str_res, len+1, format, ap);
#else
    int ret = vasprintf(&str_res, format, ap);
    if (ret == -1) {
        return NULL;
    }
#endif
   return str_res;
}

char *g_strndup(const char *str, size_t n)
{
   /* try to mimic glib's g_strndup */
   char *res = calloc(n + 1, 1);
   strncpy(res, str, n);
   return res;
}

void g_strfreev(char **str_array)
{
   char **p = str_array;
   if (p) {
      while (*p) {
         free(*p++);
      }
   }
   free(str_array);
}

gpointer g_memdup(gconstpointer mem, size_t byte_size)
{
   if (mem) {
      void *res = g_malloc(byte_size);
      memcpy(res, mem, byte_size);
      return res;
   }
   return NULL; 
}

gpointer g_new_(size_t sz, size_t n_structs)
{
   size_t need = sz * n_structs;
   if ((need / sz) != n_structs) return NULL;
   return g_malloc(need);
}

gpointer g_new0_(size_t sz, size_t n_structs)
{
   size_t need = sz * n_structs;
   if ((need / sz) != n_structs) return NULL;
   return g_malloc0(need);
}

gpointer g_renew_(size_t sz, gpointer mem, size_t n_structs)
{
   size_t need = sz * n_structs;
   if ((need / sz) != n_structs) return NULL;
   return g_realloc(mem, need);
}

/**
 * g_strconcat:
 * @string1: the first string to add, which must not be %NULL
 * @Varargs: a %NULL-terminated list of strings to append to the string
 *
 * Concatenates all of the given strings into one long string.
 * The returned string should be freed with g_free() when no longer needed.
 *
 * Note that this function is usually not the right function to use to
 * assemble a translated message from pieces, since proper translation
 * often requires the pieces to be reordered.
 *
 * <warning><para>The variable argument list <emphasis>must</emphasis> end
 * with %NULL. If you forget the %NULL, g_strconcat() will start appending
 * random memory junk to your string.</para></warning>
 *
 * Returns: a newly-allocated string containing all the string arguments
 */
gchar* g_strconcat (const gchar *string1, ...)
{
   va_list ap;
   char *res;
   size_t sz = strlen(string1);
   va_start(ap, string1);
   while (1) {
      char *arg = va_arg(ap, char*);
      if (arg == NULL) break;
      sz += strlen(arg);
   }
   va_end(ap);
   res = g_malloc(sz + 1);
   strcpy(res, string1);
   va_start(ap, string1);
   while (1) {
      char *arg = va_arg(ap, char*);
      if (arg == NULL) break;
      strcat(res, arg);
   }
   va_end(ap);
   return res;
}

/**
 * g_strsplit:
 * @string: a string to split.
 * @delimiter: a string which specifies the places at which to split the string.
 *     The delimiter is not included in any of the resulting strings, unless
 *     @max_tokens is reached.
 * @max_tokens: the maximum number of pieces to split @string into. If this is
 *              less than 1, the string is split completely.
 *
 * Splits a string into a maximum of @max_tokens pieces, using the given
 * @delimiter. If @max_tokens is reached, the remainder of @string is appended
 * to the last token.
 *
 * As a special case, the result of splitting the empty string "" is an empty
 * vector, not a vector containing a single string. The reason for this
 * special case is that being able to represent a empty vector is typically
 * more useful than consistent handling of empty elements. If you do need
 * to represent empty elements, you'll need to check for the empty string
 * before calling g_strsplit().
 *
 * Return value: a newly-allocated %NULL-terminated array of strings. Use
 *    g_strfreev() to free it.
 **/
gchar** g_strsplit (const gchar *string,
            const gchar *delimiter,
            gint         max_tokens)
{
  GSList *string_list = NULL, *slist;
  gchar **str_array, *s;
  guint n = 0;
  const gchar *remainder;

  if (string == NULL) return NULL;
  if (delimiter == NULL) return NULL;
  if (delimiter[0] == '\0') return NULL;

  if (max_tokens < 1)
    max_tokens = G_MAXINT;

  remainder = string;
  s = strstr (remainder, delimiter);
  if (s)
    {
      gsize delimiter_len = strlen (delimiter);

      while (--max_tokens && s)
        {
          gsize len;

          len = s - remainder;
          string_list = g_slist_prepend (string_list,
                                         g_strndup (remainder, len));
          n++;
          remainder = s + delimiter_len;
          s = strstr (remainder, delimiter);
        }
    }
  if (*string)
    {
      n++;
      string_list = g_slist_prepend (string_list, g_strdup (remainder));
    }

  str_array = g_new (gchar*, n + 1);

  str_array[n--] = NULL;
  for (slist = string_list; slist; slist = slist->next)
    str_array[n--] = slist->data;

  g_slist_free (string_list);

  return str_array;
}

static const char base64_alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static gsize g_base64_encode_step(const guchar *in, gsize len,
                                  gboolean break_lines,
                                  gchar *out, gint *state,
                                  gint *save)
{
  char *outptr;
  const guchar *inptr;

  if (in == NULL || out == NULL || state == NULL || save == NULL) {
    return 0;
  }

  if (len <= 0) {
    return 0;
  }

  inptr = in;
  outptr = out;

  if (len + ((char *) save) [0] > 2)
  {
    const guchar *inend = in + len - 2;
    int c1, c2, c3;
    int already;

    already = *state;

    switch (((char *) save)[0])
    {
    case 1:
      c1 = ((unsigned char *) save)[1];
      goto skip1;
    case 2:
      c1 = ((unsigned char *) save)[1];
      c2 = ((unsigned char *) save)[2];
      goto skip2;
    }

    /*
     * yes, we jump into the loop, no i'm not going to change it,
     * it's beautiful!
     */
    while (inptr < inend)
    {
      c1 = *inptr++;
    skip1:
      c2 = *inptr++;
    skip2:
      c3 = *inptr++;
      *outptr++ = base64_alphabet[c1 >> 2];
      *outptr++ = base64_alphabet[c2 >> 4 | ((c1 & 0x3) << 4)];
      *outptr++ = base64_alphabet[((c2 & 0x0f) << 2) | (c3 >> 6)];
      *outptr++ = base64_alphabet[c3 & 0x3f];
      /* this is a bit ugly ... */
      if (break_lines && (++already) >= 19)
      {
          *outptr++ = '\n';
          already = 0;
      }
    }

    ((char *)save)[0] = 0;
    len = 2 - (inptr - inend);
    *state = already;
  }

  if (len > 0)
  {
      char *saveout;

      /* points to the slot for the next char to save */
      saveout = & (((char *)save)[1]) + ((char *)save)[0];

      /* len can only be 0 1 or 2 */
      switch (len)
      {
      case 2: *saveout++ = *inptr++;
      case 1: *saveout++ = *inptr++;
      }
      ((char *) save)[0] += len;
  }

  return outptr - out;
}

gsize g_base64_encode_close(gboolean break_lines, gchar *out,
                            gint *state, gint *save)
{
  int c1, c2;
  char *outptr = out;

  if (out == NULL || state == NULL || save == NULL) {
    return 0;
  }

  c1 = ((unsigned char *) save)[1];
  c2 = ((unsigned char *) save)[2];

  switch (((char *) save)[0])
  {
  case 2:
    outptr[2] = base64_alphabet[((c2 &0x0f) << 2)];
    g_assert(outptr[2] != 0);
    goto skip;
  case 1:
    outptr[2] = '=';
    c2 = 0;  /* saved state here is not relevant */
  skip:
    outptr[0] = base64_alphabet[c1 >> 2 ];
    outptr[1] = base64_alphabet[c2 >> 4 | ((c1 & 0x3) << 4)];
    outptr[3] = '=';
    outptr += 4;
    break;
  }
  if (break_lines) {
    *outptr++ = '\n';
  }

  *save = 0;
  *state = 0;

  return outptr - out;
}

gchar *g_base64_encode(const guchar *data, gsize len)
{
  gchar *out;
  gint state = 0, outlen;
  gint save = 0;

  if (data == NULL && len != 0) {
    return NULL;
  }

  /* We can use a smaller limit here, since we know the saved state is 0,
     +1 is needed for trailing \0, also check for unlikely integer overflow */
  if (len >= ((SIZE_MAX - 1) / 4 - 1) * 3) {
    //g_error("%s: input too large for Base64 encoding (%"G_GSIZE_FORMAT" chars)",
    //    G_STRLOC, len);
    return NULL;
  }

  out = g_malloc((len / 3 + 1) * 4 + 1);

  outlen = g_base64_encode_step(data, len, FALSE, out, &state, &save);
  outlen += g_base64_encode_close(FALSE, out + outlen, &state, &save);
  out[outlen] = '\0';

  return (gchar *) out;
}

static const unsigned char mime_base64_rank[256] = {
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
  255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};

static gsize g_base64_decode_step(const gchar  *in, gsize len,
                                  guchar *out, gint *state,
                                  guint *save)
{
  const guchar *inptr;
  guchar *outptr;
  const guchar *inend;
  guchar c, rank;
  guchar last[2];
  unsigned int v;
  int i;

  if (in == NULL || out == NULL || state == NULL || save == NULL) {
    return 0;
  }

  if (len <= 0) {
    return 0;
  }

  inend = (const guchar *)in+len;
  outptr = out;

  /* convert 4 base64 bytes to 3 normal bytes */
  v = *save;
  i = *state;

  last[0] = last[1] = 0;

  /* we use the sign in the state to determine if we got a padding character
     in the previous sequence */
  if (i < 0)
  {
    i = -i;
    last[0] = '=';
  }

  inptr = (const guchar *)in;
  while (inptr < inend)
  {
    c = *inptr++;
    rank = mime_base64_rank[c];
    if (rank != 0xff)
    {
      last[1] = last[0];
      last[0] = c;
      v = (v << 6) | rank;
      i++;
      if (i == 4)
      {
        *outptr++ = v >> 16;
        if (last[1] != '=') {
          *outptr++ = v >> 8;
        }
        if (last[0] != '=') {
          *outptr++ = v;
        }
        i = 0;
      }
    }
  }

  *save = v;
  *state = last[0] == '=' ? -i : i;

  return outptr - out;
}

guchar *g_base64_decode(const gchar *text, gsize *out_len)
{
  guchar *ret;
  gsize input_length;
  gint state = 0;
  guint save = 0;

  if (text == NULL || out_len == NULL) {
    return NULL;
  }

  input_length = strlen(text);

  /* We can use a smaller limit here, since we know the saved state is 0,
     +1 used to avoid calling g_malloc0(0), and hence returning NULL */
  ret = g_malloc0((input_length / 4) * 3 + 1);

  *out_len = g_base64_decode_step(text, input_length, ret, &state, &save);

  return ret;
}

guchar *g_base64_decode_inplace(gchar *text, gsize *out_len)
{
  gint input_length, state = 0;
  guint save = 0;

  if (text == NULL || out_len == NULL) {
    return NULL;
  }

  input_length = strlen(text);

  if (input_length <= 1) {
    return NULL;
  }

  *out_len = g_base64_decode_step(text, input_length, (guchar *) text, &state, &save);

  return (guchar *) text;
}

/** SECTION: unicode
 */

static const gchar utf8_skip_data[256] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,6,6,1,1
};

const gchar * const g_utf8_skip = utf8_skip_data;

char* g_utf8_strreverse(const gchar *str, long long len)
{
  gchar *r, *result;
  const gchar *p;

  if (len < 0)
    len = strlen (str);

  result = g_new (gchar, len + 1);
  r = result + len;
  p = str;
  while (r > result)
    {
      gchar *m, skip = g_utf8_skip[*(guchar*) p];
      r -= skip;
      for (m = r; skip; skip--)
        *m++ = *p++;
    }
  result[len] = 0;

  return result;
}

/**
 * SECTION:patterns
 * @title: Glob-style pattern matching
 * @short_description: matches strings against patterns containing '*'
 *                     (wildcard) and '?' (joker)
 *
 * The g_pattern_match* functions match a string
 * against a pattern containing '*' and '?' wildcards with similar
 * semantics as the standard glob() function: '*' matches an arbitrary,
 * possibly empty, string, '?' matches an arbitrary character.
 *
 * Note that in contrast to glob(), the '/' character can be matched by
 * the wildcards, there are no '[...]' character ranges and '*' and '?'
 * can not be escaped to include them literally in a pattern.
 *
 * When multiple strings must be matched against the same pattern, it
 * is better to compile the pattern to a #GPatternSpec using
 * g_pattern_spec_new() and use g_pattern_match_string() instead of
 * g_pattern_match_simple(). This avoids the overhead of repeated
 * pattern compilation.
 **/

/**
 * GPatternSpec:
 *
 * A GPatternSpec struct is the 'compiled' form of a pattern. This
 * structure is opaque and its fields cannot be accessed directly.
 */

/* keep enum and structure of gpattern.c and patterntest.c in sync */
typedef enum
{
  G_MATCH_ALL,       /* "*A?A*" */
  G_MATCH_ALL_TAIL,  /* "*A?AA" */
  G_MATCH_HEAD,      /* "AAAA*" */
  G_MATCH_TAIL,      /* "*AAAA" */
  G_MATCH_EXACT,     /* "AAAAA" */
  G_MATCH_LAST
} GMatchType;

struct _GPatternSpec
{
  GMatchType match_type;
  guint      pattern_length;
  guint      min_length;
  guint      max_length;
  gchar     *pattern;
};


/* --- functions --- */
static inline int
g_pattern_ph_match (const char *match_pattern,
        const char *match_string,
        int    *wildcard_reached_p)
{
  const char *pattern, *string;
  char ch;

  pattern = match_pattern;
  string = match_string;

  ch = *pattern;
  pattern++;
  while (ch)
    {
      switch (ch)
  {
  case '?':
    if (!*string)
      return FALSE;
    string = g_utf8_next_char (string);
    break;

  case '*':
    *wildcard_reached_p = TRUE;
    do
      {
        ch = *pattern;
        pattern++;
        if (ch == '?')
    {
      if (!*string)
        return FALSE;
      string = g_utf8_next_char (string);
    }
      }
    while (ch == '*' || ch == '?');
    if (!ch)
      return TRUE;
    do
      {
              int next_wildcard_reached = FALSE;
        while (ch != *string)
    {
      if (!*string)
        return FALSE;
      string = g_utf8_next_char (string);
    }
        string++;
        if (g_pattern_ph_match (pattern, string, &next_wildcard_reached))
    return TRUE;
              if (next_wildcard_reached)
                /* the forthcoming pattern substring up to the next wildcard has
                 * been matched, but a mismatch occoured for the rest of the
                 * pattern, following the next wildcard.
                 * there's no need to advance the current match position any
                 * further if the rest pattern will not match.
                 */
    return FALSE;
      }
    while (*string);
    break;

  default:
    if (ch == *string)
      string++;
    else
      return FALSE;
    break;
  }

      ch = *pattern;
      pattern++;
    }

  return *string == 0;
}

/**
 * g_pattern_match:
 * @pspec: a #GPatternSpec
 * @string_length: the length of @string (in bytes, i.e. strlen(),
 *     not g_utf8_strlen())
 * @string: the UTF-8 encoded string to match
 * @string_reversed: (nullable): the reverse of @string or %NULL
 *
 * Matches a string against a compiled pattern. Passing the correct
 * length of the string given is mandatory. The reversed string can be
 * omitted by passing %NULL, this is more efficient if the reversed
 * version of the string to be matched is not at hand, as
 * g_pattern_match() will only construct it if the compiled pattern
 * requires reverse matches.
 *
 * Note that, if the user code will (possibly) match a string against a
 * multitude of patterns containing wildcards, chances are high that
 * some patterns will require a reversed string. In this case, it's
 * more efficient to provide the reversed string to avoid multiple
 * constructions thereof in the various calls to g_pattern_match().
 *
 * Note also that the reverse of a UTF-8 encoded string can in general
 * not be obtained by g_strreverse(). This works only if the string
 * does not contain any multibyte characters. GLib offers the
 * g_utf8_strreverse() function to reverse UTF-8 encoded strings.
 *
 * Returns: %TRUE if @string matches @pspec
 **/
int
g_pattern_match (GPatternSpec *pspec,
     unsigned int string_length,
     const char   *string,
     const char   *string_reversed)
{
  if (!pspec) {
    return 0;
  }

  if (!string) {
    return 0;
  }

  if (string_length < pspec->min_length ||
      string_length > pspec->max_length)
    return FALSE;

  switch (pspec->match_type)
    {
      int dummy;
    case G_MATCH_ALL:
      return g_pattern_ph_match (pspec->pattern, string, &dummy);
    case G_MATCH_ALL_TAIL:
      if (string_reversed)
  return g_pattern_ph_match (pspec->pattern, string_reversed, &dummy);
      else
  {
          int result;
          char *tmp;
    tmp = g_utf8_strreverse (string, string_length);
    result = g_pattern_ph_match (pspec->pattern, tmp, &dummy);
    g_free (tmp);
    return result;
  }
    case G_MATCH_HEAD:
      if (pspec->pattern_length == string_length)
  return strcmp (pspec->pattern, string) == 0;
      else if (pspec->pattern_length)
  return strncmp (pspec->pattern, string, pspec->pattern_length) == 0;
      else
  return TRUE;
    case G_MATCH_TAIL:
      if (pspec->pattern_length)
        return strcmp (pspec->pattern, string + (string_length - pspec->pattern_length)) == 0;
      else
  return TRUE;
    case G_MATCH_EXACT:
      if (pspec->pattern_length != string_length)
        return FALSE;
      else
        return strcmp (pspec->pattern, string) == 0;
    default:
      return FALSE;
    }
}

/**
 * g_pattern_spec_new:
 * @pattern: a zero-terminated UTF-8 encoded string
 *
 * Compiles a pattern to a #GPatternSpec.
 *
 * Returns: a newly-allocated #GPatternSpec
 **/
GPatternSpec*
g_pattern_spec_new (const char *pattern)
{
  GPatternSpec *pspec;
  int seen_joker = FALSE, seen_wildcard = FALSE, more_wildcards = FALSE;
  int hw_pos = -1, tw_pos = -1, hj_pos = -1, tj_pos = -1;
  int follows_wildcard = FALSE;
  unsigned int pending_jokers = 0;
  const char *s;
  char *d;
  unsigned int i;

  if (!pattern) {
    return NULL;
  }

  /* canonicalize pattern and collect necessary stats */
  pspec = g_new (GPatternSpec, 1);
  pspec->pattern_length = strlen (pattern);
  pspec->min_length = 0;
  pspec->max_length = 0;
  pspec->pattern = g_new (gchar, pspec->pattern_length + 1);
  d = pspec->pattern;
  for (i = 0, s = pattern; *s != 0; s++)
    {
      switch (*s)
  {
  case '*':
    if (follows_wildcard) /* compress multiple wildcards */
      {
        pspec->pattern_length--;
        continue;
      }
    follows_wildcard = TRUE;
    if (hw_pos < 0)
      hw_pos = i;
    tw_pos = i;
    break;
  case '?':
    pending_jokers++;
    pspec->min_length++;
    pspec->max_length += 4; /* maximum UTF-8 character length */
    continue;
  default:
    for (; pending_jokers; pending_jokers--, i++) {
      *d++ = '?';
        if (hj_pos < 0)
       hj_pos = i;
      tj_pos = i;
    }
    follows_wildcard = FALSE;
    pspec->min_length++;
    pspec->max_length++;
    break;
  }
      *d++ = *s;
      i++;
    }
  for (; pending_jokers; pending_jokers--) {
    *d++ = '?';
    if (hj_pos < 0)
      hj_pos = i;
    tj_pos = i;
  }
  *d++ = 0;
  seen_joker = hj_pos >= 0;
  seen_wildcard = hw_pos >= 0;
  more_wildcards = seen_wildcard && hw_pos != tw_pos;
  if (seen_wildcard)
    pspec->max_length = 0xffffffff;

  /* special case sole head/tail wildcard or exact matches */
  if (!seen_joker && !more_wildcards)
    {
      if (pspec->pattern[0] == '*')
  {
    pspec->match_type = G_MATCH_TAIL;
          memmove (pspec->pattern, pspec->pattern + 1, --pspec->pattern_length);
    pspec->pattern[pspec->pattern_length] = 0;
    return pspec;
  }
      if (pspec->pattern_length > 0 &&
    pspec->pattern[pspec->pattern_length - 1] == '*')
  {
    pspec->match_type = G_MATCH_HEAD;
    pspec->pattern[--pspec->pattern_length] = 0;
    return pspec;
  }
      if (!seen_wildcard)
  {
    pspec->match_type = G_MATCH_EXACT;
    return pspec;
  }
    }

  /* now just need to distinguish between head or tail match start */
  tw_pos = pspec->pattern_length - 1 - tw_pos;  /* last pos to tail distance */
  tj_pos = pspec->pattern_length - 1 - tj_pos;  /* last pos to tail distance */
  if (seen_wildcard)
    pspec->match_type = tw_pos > hw_pos ? G_MATCH_ALL_TAIL : G_MATCH_ALL;
  else /* seen_joker */
    pspec->match_type = tj_pos > hj_pos ? G_MATCH_ALL_TAIL : G_MATCH_ALL;
  if (pspec->match_type == G_MATCH_ALL_TAIL) {
    gchar *tmp = pspec->pattern;
    pspec->pattern = g_utf8_strreverse (pspec->pattern, pspec->pattern_length);
    g_free (tmp);
  }
  return pspec;
}

/**
 * g_pattern_spec_free:
 * @pspec: a #GPatternSpec
 *
 * Frees the memory allocated for the #GPatternSpec.
 **/
void
g_pattern_spec_free (GPatternSpec *pspec)
{
  if (!pspec) {
    return;
  }

  g_free (pspec->pattern);
  g_free (pspec);
}

/**
 * g_pattern_spec_equal:
 * @pspec1: a #GPatternSpec
 * @pspec2: another #GPatternSpec
 *
 * Compares two compiled pattern specs and returns whether they will
 * match the same set of strings.
 *
 * Returns: Whether the compiled patterns are equal
 **/
int
g_pattern_spec_equal (GPatternSpec *pspec1,
          GPatternSpec *pspec2)
{
  if (!pspec1) {
    return 0;
  }

  if (!pspec2) {
    return 0;
  }

  return (pspec1->pattern_length == pspec2->pattern_length &&
    pspec1->match_type == pspec2->match_type &&
    strcmp (pspec1->pattern, pspec2->pattern) == 0);
}

/**
 * g_pattern_match_string:
 * @pspec: a #GPatternSpec
 * @string: the UTF-8 encoded string to match
 *
 * Matches a string against a compiled pattern. If the string is to be
 * matched against more than one pattern, consider using
 * g_pattern_match() instead while supplying the reversed string.
 *
 * Returns: %TRUE if @string matches @pspec
 **/
int
g_pattern_match_string (GPatternSpec *pspec,
      const char  *string)
{
  if (!pspec) {
    return 0;
  }

  if (!string) {
    return 0;
  }

  return g_pattern_match (pspec, strlen (string), string, NULL);
}

/**
 * g_pattern_match_simple:
 * @pattern: the UTF-8 encoded pattern
 * @string: the UTF-8 encoded string to match
 *
 * Matches a string against a pattern given as a string. If this
 * function is to be called in a loop, it's more efficient to compile
 * the pattern once with g_pattern_spec_new() and call
 * g_pattern_match_string() repeatedly.
 *
 * Returns: %TRUE if @string matches @pspec
 **/
int
g_pattern_match_simple (const char *pattern,
      const char *string)
{
  GPatternSpec *pspec;
  int ergo;

  if (!pattern) {
    return 0;
  }

  if (!string) {
    return 0;
  }

  pspec = g_pattern_spec_new (pattern);
  ergo = g_pattern_match (pspec, strlen (string), string, NULL);
  g_pattern_spec_free (pspec);

  return ergo;
}
