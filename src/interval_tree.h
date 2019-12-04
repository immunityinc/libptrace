/*
 * Copyright (C) 2019, Cyxtera Cybersecurity, Inc.  All rights reserved.
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
 *
 * THE CODE AND SCRIPTS POSTED ON THIS WEBSITE ARE PROVIDED ON AN "AS IS" BASIS
 * AND YOUR USE OF SUCH CODE AND/OR SCRIPTS IS AT YOUR OWN RISK.  CYXTERA
 * DISCLAIMS ALL EXPRESS AND IMPLIED WARRANTIES, EITHER IN FACT OR BY OPERATION
 * OF LAW, STATUTORY OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, ALL
 * WARRANTIES OF MERCHANTABILITY, TITLE, FITNESS FOR A PARTICULAR PURPOSE,
 * NON-INFRINGEMENT, ACCURACY, COMPLETENESS, COMPATABILITY OF SOFTWARE OR
 * EQUIPMENT OR ANY RESULTS TO BE ACHIEVED THEREFROM.  CYXTERA DOES NOT WARRANT
 * THAT SUCH CODE AND/OR SCRIPTS ARE OR WILL BE ERROR-FREE.  IN NO EVENT SHALL
 * CYXTERA BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, RELIANCE,
 * EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF GOODWILL, LOSS
 * OF ANTICIPATED SAVINGS, COST OF PURCHASING REPLACEMENT SERVICES, LOSS OF
 * PROFITS, REVENUE, DATA OR DATA USE, ARISING IN ANY WAY OUT OF THE USE AND/OR
 * REDISTRIBUTION OF SUCH CODE AND/OR SCRIPTS, REGARDLESS OF THE LEGAL THEORY
 * UNDER WHICH SUCH LIABILITY IS ASSERTED AND REGARDLESS OF WHETHER CYXTERA HAS
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH LIABILITY.
 *
 * interval_tree.h
 *
 * Implementation of libptrace interval trees.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Roderick Asselineau <roderick@immunityinc.com>
 *
 */
#ifndef __INTERVAL_TREE_H
#define __INTERVAL_TREE_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "avl.h"

struct interval_tree
{
        struct avl_tree tree;
};

struct interval_tree_node
{
        unsigned long max;
        struct avl_node avl_node;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Internal function templates */
void printf_node(void *n);


/* API prototype templates */
#define INTERVAL_TREE_DECLARE_H(name, type, name_node,                  \
                              name_start, name_end)                     \
void interval_tree_##name##_init_tree(struct interval_tree *tree);      \
void interval_tree_##name##_init_node(type *leaf);                      \
int interval_tree_##name##_insert(struct interval_tree *tree,           \
                                  type *in);                            \
void interval_tree_##name##_delete(struct interval_tree *tree,          \
                                   type *in);                           \
type *interval_tree_##name##_find(struct interval_tree *tree,           \
                                  unsigned long start,                  \
                                  unsigned long end);                   \
type *interval_tree_##name##_find_exact(struct interval_tree *tree,     \
                                        unsigned long start,            \
                                        unsigned long end);             \
type *interval_tree_##name##_min(struct interval_tree *tree);           \
type *interval_tree_##name##_max(struct interval_tree *tree);           \
type *interval_tree_##name##_find_next(void);                           \
type *interval_tree_##name##_find_start(struct interval_tree *tree,     \
                                        unsigned long start,            \
                                        unsigned long end);             \
type *interval_tree_##name##_next(void);                                \
type *interval_tree_##name##_start(struct interval_tree *tree);         \
void interval_tree_##name##_dfs(struct avl_node *n, void (*pfn)(type *))

#ifdef __cplusplus
};
#endif

/* API body templates */

#define INTERVAL_TREE_DECLARE_C(name, type, name_node,                  \
                              name_start, name_end)                     \
                                                                        \
static void it_recalc_max(struct avl_node *an)                          \
{                                                                       \
        struct interval_tree_node *_n;                                  \
        type *__n;                                                      \
        _n = container_of(an, struct interval_tree_node, avl_node);     \
        __n = container_of(_n, type, name_node);                        \
        __n->name_node.max = __n->name_end;                             \
                                                                        \
        if(an->left) {                                                  \
                _n = container_of(an->left,                             \
                                struct interval_tree_node,              \
                                avl_node);                              \
                if(_n->max > __n->name_node.max)                        \
                        __n->name_node.max = _n->max;                   \
        }                                                               \
                                                                        \
        if(an->right) {                                                 \
                _n = container_of(an->right,                            \
                                struct interval_tree_node,              \
                                avl_node);                              \
                if(_n->max > __n->name_node.max)                        \
                        __n->name_node.max = _n->max;                   \
        }                                                               \
}                                                                       \
static void it_rotate_left(struct avl_node **root)                      \
{                                                                       \
        struct avl_node *b = *root;                                     \
        struct avl_node *d = b->right;                                  \
        struct avl_node *c;                                             \
                                                                        \
        c = d->left;                                                    \
        b->right = c;                                                   \
        if (c != NULL)                                                  \
                c->parent = b;                                          \
        recalc_height(b);                                               \
                                                                        \
        d->left = b;                                                    \
        d->parent = b->parent;                                          \
        b->parent = d;                                                  \
        recalc_height(d);                                               \
                                                                        \
        *root = d;                                                      \
                                                                        \
        it_recalc_max(d);                                               \
        it_recalc_max(b);                                               \
                                                                        \
        struct avl_node *_n = d->parent;                                \
        while(_n) {                                                     \
                it_recalc_max(_n);                                      \
                _n = _n->parent;                                        \
        }                                                               \
}                                                                       \
                                                                        \
static void it_rotate_right(struct avl_node **root)                     \
{                                                                       \
        struct avl_node *d = *root;                                     \
        struct avl_node *b = d->left;                                   \
        struct avl_node *c;                                             \
                                                                        \
        c = b->right;                                                   \
        d->left = c;                                                    \
        if (c != NULL)                                                  \
                c->parent = d;                                          \
        recalc_height(d);                                               \
                                                                        \
        b->right = d;                                                   \
        b->parent = d->parent;                                          \
        d->parent = b;                                                  \
        recalc_height(b);                                               \
                                                                        \
        *root = b;                                                      \
                                                                        \
        it_recalc_max(d);                                               \
        it_recalc_max(b);                                               \
                                                                        \
        struct avl_node *_n = d->parent;                                \
        while(_n) {                                                     \
                it_recalc_max(_n);                                      \
                _n = _n->parent;                                        \
        }                                                               \
}                                                                       \
                                                                        \
static void it_rotate_left_right(struct avl_node **root)                \
{                                                                       \
        struct avl_node *f = *root;                                     \
        struct avl_node *b = f->left;                                   \
        struct avl_node *d = b->right;                                  \
        struct avl_node *c;                                             \
        struct avl_node *e;                                             \
                                                                        \
        c = d->left;                                                    \
        b->right = c;                                                   \
        if (c != NULL)                                                  \
                c->parent = b;                                          \
        recalc_height(b);                                               \
                                                                        \
        e = d->right;                                                   \
        f->left = e;                                                    \
        if (e != NULL)                                                  \
                e->parent = f;                                          \
        recalc_height(f);                                               \
                                                                        \
        d->left = b;                                                    \
        d->right = f;                                                   \
        d->parent = f->parent;                                          \
        b->parent = d;                                                  \
        f->parent = d;                                                  \
        recalc_height(d);                                               \
                                                                        \
        *root = d;                                                      \
                                                                        \
        it_recalc_max(b);                                               \
        it_recalc_max(f);                                               \
        it_recalc_max(d);                                               \
                                                                        \
        struct avl_node *_n = d->parent;                                \
        while(_n) {                                                     \
                it_recalc_max(_n);                                      \
                _n = _n->parent;                                        \
        }                                                               \
}                                                                       \
                                                                        \
static void it_rotate_right_left(struct avl_node **root)                \
{                                                                       \
        struct avl_node *b = *root;                                     \
        struct avl_node *f = b->right;                                  \
        struct avl_node *d = f->left;                                   \
        struct avl_node *c;                                             \
        struct avl_node *e;                                             \
                                                                        \
        c = d->left;                                                    \
        b->right = c;                                                   \
        if (c != NULL)                                                  \
                c->parent = b;                                          \
        recalc_height(b);                                               \
                                                                        \
        e = d->right;                                                   \
        f->left = e;                                                    \
        if (e != NULL)                                                  \
                e->parent = f;                                          \
        recalc_height(f);                                               \
                                                                        \
        d->left = b;                                                    \
        d->right = f;                                                   \
        d->parent = b->parent;                                          \
        b->parent = d;                                                  \
        f->parent = d;                                                  \
        recalc_height(d);                                               \
                                                                        \
        *root = d;                                                      \
                                                                        \
        it_recalc_max(b);                                               \
        it_recalc_max(f);                                               \
        it_recalc_max(d);                                               \
                                                                        \
        struct avl_node *_n = d->parent;                                \
        while(_n) {                                                     \
                it_recalc_max(_n);                                      \
                _n = _n->parent;                                        \
        }                                                               \
}                                                                       \
                                                                        \
static void it_rebalance_node(struct avl_node **_root)                  \
{                                                                       \
        struct avl_node *root = *_root;                                 \
        int bal;                                                        \
                                                                        \
        bal = balance(root);                                            \
        if (bal == -2) {                                                \
                if (balance(root->left) <= 0)                           \
                        it_rotate_right(_root);                         \
                else                                                    \
                        it_rotate_left_right(_root);                    \
        } else if (bal == 2) {                                          \
                if (balance(root->right) < 0)                           \
                        it_rotate_right_left(_root);                    \
                else                                                    \
                        it_rotate_left(_root);                          \
        } else {                                                        \
                struct avl_node *_n = root;                             \
                while(_n) {                                             \
                        it_recalc_max(_n);                              \
                        _n = _n->parent;                                \
                }                                                       \
        }                                                               \
}                                                                       \
                                                                        \
static void it_rebalance_path(struct avl_tree *tree, struct avl_node *an)\
{                                                                       \
        while (an != NULL) {                                            \
                int old_height;                                         \
                struct avl_node **ref;                                  \
                                                                        \
                old_height = an->height;                                \
                recalc_height(an);                                      \
                                                                        \
                ref = find_reference(tree, an);                         \
                it_rebalance_node(ref);                                 \
                an = *ref;                                              \
                                                                        \
                if (old_height == an->height)                           \
                        break;                                          \
                                                                        \
                an = an->parent;                                        \
        }                                                               \
}                                                                       \
                                                                        \
static inline int                                                       \
__interval_tree_##name##_compare(struct avl_node *__a,                  \
                                 struct avl_node *__b)                  \
{                                                                       \
        struct interval_tree_node *_a =                                 \
                container_of(__a, struct interval_tree_node, avl_node); \
        struct interval_tree_node *_b =                                 \
                container_of(__b, struct interval_tree_node, avl_node); \
        type *a = container_of(_a, type, name_node);                    \
        type *b = container_of(_b, type, name_node);                    \
                                                                        \
        if (a->name_start < b->name_start)                              \
                return -1;                                              \
                                                                        \
        if (a->name_start > b->name_start)                              \
                return 1;                                               \
                                                                        \
        return 0;                                                       \
}                                                                       \
                                                                        \
void interval_tree_##name##_init_tree(struct interval_tree *tree)       \
{                                                                       \
        INIT_AVL_TREE(&tree->tree, __interval_tree_##name##_compare);   \
}                                                                       \
                                                                        \
void interval_tree_##name##_init_node(type *leaf)                       \
{                                                                       \
        INIT_AVL_NODE(&leaf->name_node.avl_node);                       \
        leaf->name_node.max=0;                                          \
}                                                                       \
int interval_tree_##name##_insert(struct interval_tree *tree, type *in) \
{                                                                       \
        struct avl_node *an = &in->name_node.avl_node;                  \
        struct avl_tree *_tree = &tree->tree;                           \
        struct avl_node *p = NULL;                                      \
        struct avl_node **pp;                                           \
                                                                        \
        it_recalc_max(an);                                              \
        pp = &_tree->root;                                              \
        while (*pp != NULL) {                                           \
                int ret;                                                \
                                                                        \
                p = *pp;                                                \
                                                                        \
                ret = _tree->compare(an, p);                            \
                if (ret < 0)                                            \
                        pp = &p->left;                                  \
                else                                                    \
                        pp = &p->right;                                 \
        }                                                               \
        an->left = NULL;                                                \
        an->right = NULL;                                               \
        an->parent = p;                                                 \
        an->height = 1;                                                 \
        *pp = an;                                                       \
        it_rebalance_path(_tree, p);                                    \
        return 0;                                                       \
}                                                                       \
void interval_tree_##name##_delete(struct interval_tree *tree, type *in)\
{                                                                       \
        struct avl_node *an = &in->name_node.avl_node;                  \
        struct avl_tree *_tree = &tree->tree;                           \
        struct avl_node *p;                                             \
                                                                        \
        if (an->left == NULL && an->right == NULL)                      \
                p = avl_tree_delete_leaf(_tree, an);                    \
        else                                                            \
                p = avl_tree_delete_nonleaf(_tree, an);                 \
                                                                        \
        it_rebalance_path(_tree, p);                                    \
        an->left = NULL;                                                \
        an->right = NULL;                                               \
        an->parent = NULL;                                              \
        an->height = 0;                                                 \
        in->name_node.max = 0;                                          \
}                                                                       \
static inline int __interval_tree_##name##_filter(type *tn,             \
                                       int filter_type,                 \
                                       unsigned long start,             \
                                       unsigned long end)               \
{                                                                       \
        if(filter_type == 0) {                                          \
                if(tn->name_start >= start && tn->name_start <= end)    \
                        return 1;                                       \
                if( tn->name_end >= start && tn->name_end <= end)       \
                        return 1;                                       \
                if( tn->name_start <= start && tn->name_end >= end)     \
                        return 1;                                       \
        } else {                                                        \
                if(tn->name_start == start && tn->name_end == end)      \
                        return 1;                                       \
        }                                                               \
        return 0;                                                       \
}                                                                       \
static inline type *__interval_tree_##name##_find(struct avl_node *an,  \
                                           unsigned long start,         \
                                           unsigned long end,           \
                                           int filter_type)             \
{                                                                       \
        while (an != NULL) {                                            \
                struct interval_tree_node *in =                         \
                        container_of(an,                                \
                        struct interval_tree_node,                      \
                        avl_node);                                      \
                type *tn = container_of(in, type, name_node);           \
                                                                        \
                if(__interval_tree_##name##_filter(tn,                  \
                                                   filter_type,         \
                                                   start,               \
                                                   end))                \
                        return tn;                                      \
                                                                        \
                if (an->left != NULL) {                                 \
                        struct interval_tree_node *inl =                \
                                container_of(an->left,                  \
                                             struct interval_tree_node, \
                                             avl_node);                 \
                                                                        \
                        if (start <= inl->max) {                        \
                                an = an->left;                          \
                        } else {                                        \
                                an = an->right;                         \
                        }                                               \
                } else {                                                \
                        an = an->right;                                 \
                }                                                       \
        }                                                               \
        return NULL;                                                    \
}                                                                       \
                                                                        \
type *interval_tree_##name##_find(struct interval_tree *tree,           \
                                  unsigned long start,                  \
                                  unsigned long end)                    \
{                                                                       \
        struct avl_node *an = tree->tree.root;                          \
        return __interval_tree_##name##_find(an, start, end, 0);        \
}                                                                       \
type *interval_tree_##name##_find_exact(struct interval_tree *tree,     \
                                  unsigned long start,                  \
                                  unsigned long end)                    \
{                                                                       \
        struct avl_node *an = tree->tree.root;                          \
        return __interval_tree_##name##_find(an, start, end, 1);        \
}                                                                       \
type *interval_tree_##name##_min(struct interval_tree *tree)            \
{                                                                       \
        struct avl_node *an;                                            \
        if(!tree || !tree->tree.root)                                   \
                return NULL;                                            \
                                                                        \
        an = tree->tree.root;                                           \
        while (an && an->left) {                                        \
                an = an->left;                                          \
        }                                                               \
        struct interval_tree_node *in =                                 \
        container_of(an, struct interval_tree_node, avl_node);          \
        type *tn = container_of(in, type, name_node);                   \
                                                                        \
        return tn;                                                      \
}                                                                       \
type *interval_tree_##name##_max(struct interval_tree *tree)            \
{                                                                       \
        struct avl_node *an;                                            \
        if(!tree || !tree->tree.root)                                   \
                return NULL;                                            \
                                                                        \
        an = tree->tree.root;                                           \
        while (an && an->right) {                                       \
                an = an->right;                                         \
        }                                                               \
        struct interval_tree_node *in =                                 \
        container_of(an, struct interval_tree_node, avl_node);          \
        type *tn = container_of(in, type, name_node);                   \
                                                                        \
        return tn;                                                      \
}                                                                       \
                                                                        \
static type *__internal_iter_node = NULL;                               \
static unsigned long __internal_iter_begin = 0;                         \
static unsigned long __internal_iter_end = 0;                           \
                                                                        \
static inline                                                           \
struct avl_node *_interval_tree_##name##_next(struct avl_node *an)      \
{                                                                       \
                                                                        \
        if (an->right != NULL) {                                        \
                an = an->right;                                         \
                while (an->left != NULL)                                \
                        an = an->left;                                  \
                                                                        \
        } else {                                                        \
                while (an && an->parent && an == an->parent->right) {   \
                        an = an->parent;                                \
                }                                                       \
                an = an->parent;                                        \
        }                                                               \
        return an;                                                      \
}                                                                       \
static inline                                                           \
type *_interval_tree_##name##_find_next(void)                           \
{                                                                       \
        if(!__internal_iter_node) return NULL;                          \
                                                                        \
        struct avl_node *an =                                           \
                &__internal_iter_node->name_node.avl_node;              \
                                                                        \
        an = _interval_tree_##name##_next(an);                          \
        if(!an) return NULL;                                            \
        struct interval_tree_node *in =                                 \
                container_of(an, struct interval_tree_node, avl_node);  \
        __internal_iter_node =                                          \
                container_of(in, type, name_node);                      \
        return __internal_iter_node;                                    \
}                                                                       \
type *interval_tree_##name##_find_next(void)                            \
{                                                                       \
        type *tn;                                                       \
        while(1) {                                                      \
                tn = _interval_tree_##name##_find_next();               \
                if(!tn) break;                                          \
                if(__interval_tree_##name##_filter(                     \
                        tn, 0,                                          \
                        __internal_iter_begin,                          \
                        __internal_iter_begin))                         \
                        break;                                          \
        }                                                               \
        return tn;                                                      \
}                                                                       \
type *interval_tree_##name##_find_start(struct interval_tree *tree,     \
                                        unsigned long start,            \
                                        unsigned long end)              \
{                                                                       \
        struct avl_node *an = avl_tree_min(&tree->tree);                \
        if(!an) return NULL;                                            \
        struct interval_tree_node *in =                                 \
                        container_of(an, struct interval_tree_node,     \
                                     avl_node);                         \
        __internal_iter_node = container_of(in, type, name_node);       \
        __internal_iter_begin = start;                                  \
        __internal_iter_end = end;                                      \
        if(__interval_tree_##name##_filter(                             \
                        __internal_iter_node, 0,                        \
                        __internal_iter_begin,                          \
                        __internal_iter_begin))                         \
                return __internal_iter_node;                            \
        else                                                            \
                return interval_tree_##name##_find_next();              \
}                                                                       \
type *interval_tree_##name##_next(void)                                 \
{                                                                       \
        __internal_iter_node =                                          \
                _interval_tree_##name##_find_next();                    \
        return __internal_iter_node;                                    \
}                                                                       \
type *interval_tree_##name##_start(struct interval_tree *tree)          \
{                                                                       \
        struct avl_node *an = avl_tree_min(&tree->tree);                \
        if(!an) return NULL;                                            \
        struct interval_tree_node *in =                                 \
            container_of(an, struct interval_tree_node,                 \
                                     avl_node);                         \
        __internal_iter_node = container_of(in, type, name_node);       \
        __internal_iter_begin = 0;                                      \
        __internal_iter_end = 0;                                        \
        return __internal_iter_node;                                    \
}                                                                       \
void interval_tree_##name##_dfs(struct avl_node *n,                     \
                                 void (*pfn)(type *))                   \
{                                                                       \
        if(!n)                                                          \
                return;                                                 \
        struct interval_tree_node *an =                                 \
                        container_of(n,                                 \
                                     struct interval_tree_node,         \
                                     avl_node);                         \
        type *tn = container_of(an, type, name_node);                   \
        pfn(tn);                                                        \
                                                                        \
        if (n->left)                                                    \
                interval_tree_##name##_dfs(n->left, pfn);               \
        if (n->right)                                                   \
                interval_tree_##name##_dfs(n->right, pfn);              \
        return;                                                         \
}

#endif /* __INTERVAL_TREE_H */
