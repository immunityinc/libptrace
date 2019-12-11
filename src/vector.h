/* vector.h, a C implementation for a templated vector ADT.
 *
 * Copyright (C) 2004-2019, Ronald Huizer <rhuizer@hexpedition.com>
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1 as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * version 2.1 for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 2.1 along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */
#ifndef PT_VECTOR_INTERNAL_H
#define PT_VECTOR_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>
#include <math.h>

#define VECTOR_INIT_SIZE		1024
#define VECTOR_REORDER_TRESHOLD		2
#define VECTOR_GROW_SCALE		2.0

#define VECTOR_INIT	{ NULL, 0U, 0, 0 }

#define VECTOR_DECLARE(name, type)					\
	VECTOR_DECLARE_STRUCT(name, type)				\
	VECTOR_DECLARE_PROTOTYPES(name, type)

#define VECTOR_DEFINE(name, type)					\
	VECTOR_DEFINE_INIT(name)					\
	VECTOR_DEFINE_DESTROY(name)					\
	VECTOR_DEFINE_GROW(name, type)					\
	VECTOR_DEFINE_SHRINK(name, type)				\
	VECTOR_DEFINE_RESIZE(name, type)				\
	VECTOR_DEFINE_REORDER(name, type)				\
	VECTOR_DEFINE_CREATE_GAP(name, type)				\
	VECTOR_DEFINE_ADD(name, type)					\
	VECTOR_DEFINE_ADD_ONE(name, type)				\
	VECTOR_DEFINE_ADD_ONE_PTR(name, type)				\
	VECTOR_DEFINE_INSERT(name, type)				\
	VECTOR_DEFINE_INSERT_ONE(name, type)				\
	VECTOR_DEFINE_INSERT_ONE_PTR(name, type)			\
	VECTOR_DEFINE_EAT_FRONT(name, type)				\
	VECTOR_DEFINE_GET_SIZE(name, type)				\
	VECTOR_DEFINE_GET_ELEMENT(name, type)				\
	VECTOR_DEFINE_GET_ELEMENT_PTR(name, type)			\
	VECTOR_DEFINE_SET_ELEMENT(name, type)				\
	VECTOR_DEFINE_SET_ELEMENT_PTR(name, type)

/* In the vector structure the following elements are used:
 *
 * - sa: number of 'type' elements allocated for this vector.
 * - start: the index of the first 'type' element of this vector.
 * - end: the index of the first 'type element after the last 'type'
 *   element of this vector.
 *
 * Note that VECTOR_INIT_SIZE is the number of 'type' elements allocated
 * for the vector, and not the number of bytes.
 */
#define VECTOR_DECLARE_STRUCT(name, type)				\
struct vector_##name {							\
	type *data;							\
	unsigned int sa;						\
	ptrdiff_t start;						\
	ptrdiff_t end;							\
};

#define VECTOR_DECLARE_PROTOTYPES(name, type)				\
struct vector_##name *vector_##name##_init(struct vector_##name *v);	\
struct vector_##name *vector_##name##_destroy(struct vector_##name *v);	\
struct vector_##name *vector_##name##_grow(struct vector_##name *v);	\
struct vector_##name *vector_##name##_shrink(struct vector_##name *v);	\
struct vector_##name *vector_##name##_resize(struct vector_##name *v,	\
                                             unsigned int size);	\
struct vector_##name *vector_##name##_reorder(struct vector_##name *v);	\
struct vector_##name *vector_##name##_create_gap(			\
	struct vector_##name *v, unsigned int index, size_t s);		\
struct vector_##name *vector_##name##_add(struct vector_##name *v,	\
                                          const type *p, size_t s);	\
struct vector_##name *vector_##name##_add_one(				\
	struct vector_##name *v, const type p);				\
struct vector_##name *vector_##name##_add_one_ptr(			\
	struct vector_##name *v, const type *p);			\
struct vector_##name *vector_##name##_insert(				\
	struct vector_##name *v,					\
	unsigned int index, const type *p, size_t s);			\
struct vector_##name *vector_##name##_insert_one(			\
	struct vector_##name *v,					\
	unsigned int index, const type p);				\
struct vector_##name *vector_##name##_insert_one_ptr(			\
	struct vector_##name *v,					\
	unsigned int index, const type *p);				\
struct vector_##name *vector_##name##_eat_front(			\
	struct vector_##name *v, unsigned int s);			\
size_t vector_##name##_get_size(struct vector_##name *v);		\
type vector_##name##_get_element(struct vector_##name *v,		\
                                 unsigned int i);			\
type *vector_##name##_get_element_ptr(					\
	struct vector_##name *v, unsigned int index);			\
struct vector_##name *vector_##name##_set_element(			\
	struct vector_##name *v, unsigned int index, const type p);	\
struct vector_##name *vector_##name##_set_element_ptr(			\
	struct vector_##name *v, unsigned int index, const type *p);

#define VECTOR_DEFINE_INIT(name)					\
/* Initialize the vector 'v' for use					\
 */									\
struct vector_##name *vector_##name##_init(struct vector_##name *v) {	\
	v->data = NULL;							\
	v->sa = v->start = v->end = 0;					\
	return v;							\
}

#define VECTOR_DEFINE_DESTROY(name)					\
/* Deallocate the contents of and reset the vector 'v'			\
 */									\
struct vector_##name *							\
vector_##name##_destroy(struct vector_##name *v)			\
{									\
	if(v->data != NULL) {						\
		free(v->data);						\
		v->data = NULL;						\
	}								\
	v->sa = v->start = v->end = 0;					\
	return v;							\
}

#define VECTOR_DEFINE_GROW(name, type)					\
/* Grow the vector 'v' in size by a factor VECTOR_GROW_SCALE.		\
 * Check for multiplication overflows and prevent them.			\
 */									\
struct vector_##name *vector_##name##_grow(struct vector_##name *v)	\
{									\
	type *data;							\
									\
	if (v->sa == 0) {						\
		v->sa = VECTOR_INIT_SIZE;				\
	} else {							\
		/* If we have an overflow, allocate as much as we can	\
		 * without screwing anything up.			\
		 */							\
		if (UINT_MAX / VECTOR_GROW_SCALE			\
		             / sizeof( type ) < v->sa) {		\
			v->sa = UINT_MAX / sizeof( type );		\
		}							\
		/* If not, we can safely perform both multiplications	\
		 */							\
		else {							\
			v->sa *= VECTOR_GROW_SCALE;			\
		}							\
	}								\
									\
	data = (type *)xrealloc(v->data, v->sa * sizeof(type));		\
	if (data == NULL)						\
		return NULL;						\
									\
	v->data = data;							\
	return v;							\
}


#define VECTOR_DEFINE_SHRINK(name, type)				\
/* If *possible* shrink the vector 'v' by a factor 2. This means that	\
 * no data in the vector will ever be lost by calling this function.	\
 */									\
struct vector_##name *vector_##name##_shrink(struct vector_##name *v)	\
{									\
	unsigned int s;							\
	type *data;							\
									\
	/* This only happens if v->data hasn't been allocated yet */	\
	if (v->sa == 0)							\
		return v;						\
									\
	/* If the new storage size is too small to hold the current	\
	 * data or would be exactly enough to hold the current data,	\
	 * we will not shrink the vector.				\
	 */								\
	if ( (s = v->sa / VECTOR_GROW_SCALE) <= v->end)			\
		return v;						\
									\
	/* Make sure we never shrink the vector to an allocated size	\
	 * smaller than VECTOR_INIT_SIZE				\
	 */								\
	v->sa = s < VECTOR_INIT_SIZE ? VECTOR_INIT_SIZE : s;		\
									\
	/* Since we're shrinking the vector here and we check vector	\
	 * growth for overflows, this multiplication is safe.		\
	 */								\
	data = (type *)xrealloc(v->data, v->sa * sizeof(type));		\
	if (data == NULL)						\
		return NULL;						\
									\
	v->data = data;							\
	return v;							\
}

#define VECTOR_DEFINE_RESIZE(name, type)				\
/* Resize the vector 'v' to the power of VECTOR_GROW_SCALE closest to	\
 * size.								\
 * This operation is *destructive*, if the vector contains elements	\
 * beyond the new size they are discarded.				\
 */									\
struct vector_##name *							\
vector_##name##_resize(struct vector_##name *v, unsigned int size)	\
{									\
	unsigned int alloc_size;					\
	type *data;							\
									\
	/* Resizing to 0 is equal to destroying the vector. */		\
	if (size == 0) {						\
		vector_##name##_destroy(v);				\
		return v;						\
	}								\
									\
	/* Reorder the vector, to reduce complexity. */			\
	vector_##name##_reorder(v);					\
									\
	/* Never shrink the vector smaller than VECTOR_INIT_SIZE */	\
	if (size < VECTOR_INIT_SIZE)					\
		size = VECTOR_INIT_SIZE;				\
									\
	/* Round the requested size up to the allocation size. */	\
	alloc_size = roundup_power(size, VECTOR_GROW_SCALE);		\
	if (alloc_size < size) {					\
		return NULL;						\
	}								\
									\
	/* Reallocate the vector to the new size. */			\
	data = (type *)xrealloc(v->data, alloc_size * sizeof(type));	\
	if (data == NULL)						\
		return NULL;						\
									\
	v->sa = alloc_size;						\
	v->end = size;							\
	v->data = data;							\
	return v;							\
}

#define VECTOR_DEFINE_REORDER(name, type)				\
/* Copies the data in the vector to eliminate a prefix of unused	\
 * space. This is induced by calling vector_eat_front().		\
 */									\
struct vector_##name *							\
vector_##name##_reorder(struct vector_##name *v)			\
{									\
	memmove(v->data, v->data + v->start,				\
		(v->end - v->start) * sizeof(type));			\
	v->end -= v->start;						\
	v->start = 0;							\
	return v;							\
}

#define VECTOR_DEFINE_CREATE_GAP(name, type)				\
struct vector_##name *							\
vector_##name##_create_gap(struct vector_##name *v,			\
                           unsigned int index, size_t s)		\
{									\
	unsigned int new = v->end + s;					\
	size_t size = vector_##name##_get_size(v);			\
									\
	/* Test wether we're not overindexing the vector.		\
	 * Note that we reserve the special case where index == size	\
	 * for adding a gap at the end of the vector, effectively	\
	 * resizing it to hold 's' more elements.			\
	 */								\
	if (index > size)						\
		return NULL;						\
									\
	/* We're not adding anything here, so we're done. */		\
	if (s == 0)							\
		return v;						\
									\
	/* Test for addition overflows */				\
	if (new < v->end || new < s)					\
		return NULL;						\
									\
	/* Allocate storage for the vector. These iterations are not as	\
	 * expensive as they look.					\
	 */								\
	while(new >= v->sa)						\
		v = vector_##name##_grow(v);				\
									\
	/* Create a gap to fit the inserted elements in. */		\
	if (index != size)						\
		memmove(v->data + v->start + index + s,			\
		        v->data + index,				\
			(size - index) * sizeof(type));			\
	v->end += s;							\
	return v;							\
}

#define VECTOR_DEFINE_ADD(name, type)					\
/* Add data to the vector.						\
 */									\
struct vector_##name *							\
vector_##name##_add(struct vector_##name *v, const type *p, size_t s)	\
{									\
	return vector_##name##_insert(v, v->end, p, s);			\
}

#define VECTOR_DEFINE_ADD_ONE(name, type)				\
/* Add data to the vector.						\
 */									\
struct vector_##name *							\
vector_##name##_add_one(struct vector_##name *v, const type p)		\
{									\
	return vector_##name##_add(v, &p, 1);				\
}

#define VECTOR_DEFINE_ADD_ONE_PTR(name, type)				\
/* Add data to the vector.						\
 */									\
struct vector_##name *							\
vector_##name##_add_one_ptr(struct vector_##name *v, const type *p)	\
{									\
	return vector_##name##_add(v, p, 1);				\
}

/* XXX: can use prefix space if available ... */
#define VECTOR_DEFINE_INSERT(name, type)				\
/* Insert 's' 'type' elements into the vector 'v' at position 'index'.	\
 */									\
struct vector_##name *							\
vector_##name##_insert(struct vector_##name *v,				\
                       unsigned int index, const type *p, size_t s)	\
{									\
	if ( vector_##name##_create_gap(v, index, s) == NULL )		\
		return NULL;						\
									\
	memcpy(v->data + v->start + index, p, s * sizeof(type));	\
	return v;							\
}

#define VECTOR_DEFINE_INSERT_ONE(name, type)				\
struct vector_##name *							\
vector_##name##_insert_one(struct vector_##name *v,			\
                           unsigned int index, const type p)		\
{									\
	return vector_##name##_insert(v, index, &p, 1);			\
}

#define VECTOR_DEFINE_INSERT_ONE_PTR(name, type)			\
struct vector_##name *							\
vector_##name##_insert_one_ptr(struct vector_##name *v,			\
                               unsigned int index, const type *p)	\
{									\
	return vector_##name##_insert(v, index, p, 1);			\
}

#define VECTOR_DEFINE_EAT_FRONT(name, type)				\
/* Discard the 's' foremost elements from the vector 'v'. If the prefix	\
 * gap this leaves grows too large, this calls vector_reorder() to	\
 * eliminate this gap.							\
 */									\
struct vector_##name *							\
vector_##name##_eat_front(struct vector_##name *v, unsigned int s)	\
{									\
	/* If we eat less data than there is, we will reorder the	\
	 * vector if the gap is larger than a				\
	 * VECTOR_REORDER_TRESHOLD'th part of the vector.		\
	 */								\
	if(s <= v->end - v->start) {					\
		if( (v->start += s) > v->sa / VECTOR_REORDER_TRESHOLD)	\
			vector_##name##_reorder(v);			\
	} else {							\
		v->start = v->end = 0;					\
	}								\
									\
	/* Shrink the vector as far as possible */			\
	while (v->end < v->sa / 2 && v->sa != VECTOR_INIT_SIZE)		\
		vector_##name##_shrink(v);				\
									\
	return v;							\
}

#define VECTOR_DEFINE_GET_SIZE(name, type)				\
/* Retrieves the size of a vector 'v'.					\
 */									\
size_t									\
vector_##name##_get_size(struct vector_##name *v)			\
{									\
	return v->end - v->start;					\
}

#define VECTOR_DEFINE_GET_ELEMENT(name, type)				\
/* Returns the vector element at index 'i'.				\
 */									\
type									\
vector_##name##_get_element(struct vector_##name *v, unsigned int i)	\
{									\
	return v->data[v->start + i];					\
}

#define VECTOR_DEFINE_GET_ELEMENT_PTR(name, type)			\
/* Returns a pointer to the vector element at index 'i'.		\
 */									\
type *									\
vector_##name##_get_element_ptr(					\
	struct vector_##name *v,					\
	unsigned int i							\
) {									\
	return &v->data[v->start + i];					\
}

#define VECTOR_DEFINE_SET_ELEMENT(name, type)				\
struct vector_##name *							\
vector_##name##_set_element(struct vector_##name *v,			\
                            unsigned int index, const type p)		\
{									\
	/* Check wether we're not overindexing. */			\
	if ( index >= vector_##name##_get_size(v) )			\
		return NULL;						\
									\
	v->data[v->start + index] = p;					\
	return v;							\
}

#define VECTOR_DEFINE_SET_ELEMENT_PTR(name, type)			\
struct vector_##name *							\
vector_##name##_set_element_ptr(struct vector_##name *v,		\
                            unsigned int index, const type *p)		\
{									\
	/* Check wether we're not overindexing. */			\
	if ( index >= vector_##name##_get_size(v) )			\
		return NULL;						\
									\
	v->data[v->start + index] = *p;					\
	return v;							\
}

/* Additional helper functions used by vector.h */
static inline unsigned int
roundup_power(unsigned int n, unsigned int exp)
{
	double l = log(n) / log(exp);
	return (unsigned int) pow(exp, ceil(l));
}

static inline int fls(int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

static inline unsigned int roundup_pow_of_two(unsigned int n)
{
        return 1U << fls(n - 1);
}

#endif	/* !PT_VECTOR_INTERNAL_H */
