/*
 * Copyright (C) 2010 Lennert Buytenhek
 *
 * Dedicated to Marija Kulikova.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version
 * 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License version 2.1 for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License version 2.1 along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street - Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
#ifndef PT_AVL_INTERNAL_H
#define PT_AVL_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

#define container_of(ptr, type, member) ({				\
	const typeof(((type *)0)->member) *ptr_ = (ptr);		\
	(type *)((char *)ptr_ - (uintptr_t)(&((type *)0)->member)); })

struct avl_node {
	struct avl_node		*left;
	struct avl_node		*right;
	struct avl_node		*parent;
	uint8_t			height;
};

struct avl_tree {
	int			(*compare)(struct avl_node *a,
					   struct avl_node *b);

	struct avl_node	*root;
};

#define AVL_TREE_INIT(comp)				\
	{ .compare = (comp), .root = NULL }

#define INIT_AVL_TREE(tree, comp)			\
	do {						\
		(tree)->compare = (comp);		\
		(tree)->root = NULL;			\
	} while (0)

#define AVL_NODE_INIT()				        \
	{ .left = NULL, .right = NULL,                  \
	  .parent = NULL,                               \
	  .height = 0 }                                 \

#define INIT_AVL_NODE(node)		        	\
	do {						\
		(node)->left = NULL;	        	\
		(node)->right = NULL;			\
		(node)->parent = NULL;			\
		(node)->height = 0;			\
	} while (0)

int avl_tree_insert(struct avl_tree *tree, struct avl_node *an);
void avl_tree_delete(struct avl_tree *tree, struct avl_node *an);
struct avl_node *avl_tree_next(struct avl_node *an);
struct avl_node *avl_tree_prev(struct avl_node *an);
struct avl_node *avl_tree_delete_leaf(struct avl_tree *tree, struct avl_node *an);
struct avl_node *avl_tree_delete_nonleaf(struct avl_tree *tree, struct avl_node *an);
int height(struct avl_node *an);
void recalc_height(struct avl_node *an);
int balance(struct avl_node *an);
void rebalance_path(struct avl_tree *tree, struct avl_node *an);
void replace_reference(struct avl_tree *tree, struct avl_node *an, struct avl_node *new_child);
struct avl_node **find_reference(struct avl_tree *tree, struct avl_node *an);

static inline int avl_tree_empty(struct avl_tree *tree)
{
	return tree->root == NULL;
}

static inline struct avl_node *avl_tree_min(struct avl_tree *tree)
{
	if (tree->root != NULL) {
		struct avl_node *an;

		an = tree->root;
		while (an->left != NULL)
			an = an->left;

		return an;
	}

	return NULL;
}

static inline struct avl_node *avl_tree_max(struct avl_tree *tree)
{
	if (tree->root != NULL) {
		struct avl_node *an;

		an = tree->root;
		while (an->right != NULL)
			an = an->right;

		return an;
	}

	return NULL;
}

#define avl_tree_for_each(an, tree) \
	for (an = avl_tree_min(tree); an != NULL; an = avl_tree_next(an))

static inline struct avl_node *avl_tree_next_safe(struct avl_node *an)
{
	return an != NULL ? avl_tree_next(an) : NULL;
}

#define avl_tree_for_each_safe(an, an2, tree) \
	for (an = avl_tree_min(tree), an2 = avl_tree_next_safe(an); \
	     an != NULL; an = an2, an2 = avl_tree_next_safe(an))

#ifdef __cplusplus
};
#endif

#endif	/* !PT_AVL_INTERNAL_H */
