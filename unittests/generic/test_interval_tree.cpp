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
 * test_interval_tree.cpp
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Roderick Asselineau <roderick@immunityinc.com>
 * 
 */
#define BOOST_TEST_MODULE windows_native
#include <cstdlib>
#include <boost/test/included/unit_test.hpp>
#include "libptrace/interval_tree.h"

struct test
{
	unsigned long foo;
	unsigned long bar;
	struct interval_tree_node node;
};

INTERVAL_TREE_DECLARE_C(test, struct test, node, foo, bar);

void printf_node(void *n_)
{
	struct test *n = (struct test *)n_;
	struct avl_node *p;
	struct interval_tree_node *p_;
	struct test *p__;

	printf("NODE [%lu,%lu]\n", n->foo, n->bar);

	if (n->node.avl_node.parent) {
		p   = n->node.avl_node.parent;
		p_  = container_of(p, struct interval_tree_node, avl_node);
		p__ = container_of(p_, struct test, node);
		printf("\t-> parent [%lu,%lu]\n", p__->foo, p__->bar);
	}

	if (n->node.avl_node.left) {
		p   = n->node.avl_node.left;
		p_  = container_of(p, struct interval_tree_node, avl_node);
		p__ = container_of(p_, struct test, node);
		printf("\t-> left [%lu,%lu]\n", p__->foo, p__->bar);
	}

	if(n->node.avl_node.right) {
		p   = n->node.avl_node.right;
		p_  = container_of(p, struct interval_tree_node, avl_node);
		p__ = container_of(p_, struct test, node);
		printf("\t-> right [%lu,%lu]\n", p__->foo, p__->bar);
	}

	printf("\t-> max %lu\n", n->node.max);
}

// We test insert/delete as well as the 4 rotations
// TODO: add already existing elt => infinite loop
BOOST_AUTO_TEST_CASE(test_insert_delete)
{
	struct interval_tree t;
	struct test n1;
	struct test n2;
	struct test n3;
	struct test n4;
	struct test n5;
	struct test n6;

	interval_tree_test_init_tree(&t);
	interval_tree_test_init_node(&n1);
	interval_tree_test_init_node(&n2);
	interval_tree_test_init_node(&n3);
	interval_tree_test_init_node(&n4);
	interval_tree_test_init_node(&n5);
	interval_tree_test_init_node(&n6);

	n1.foo = 10;
	n1.bar = 13;

	n2.foo = 11;
	n2.bar = 20;

	n3.foo = 9;
	n3.bar = 20;

	n4.foo = 8;
	n4.bar = 9;

	n5.foo = 5;
	n5.bar = 17;

	n6.foo = 9;
	n6.bar = 40;

	// triggers a RIGHT rotation
	interval_tree_test_insert(&t, &n1);
	interval_tree_test_insert(&t, &n2);
	interval_tree_test_insert(&t, &n3);
	interval_tree_test_insert(&t, &n4);
	interval_tree_test_insert(&t, &n5);

	BOOST_REQUIRE(n1.node.avl_node.left == &n4.node.avl_node);
	BOOST_REQUIRE(n1.node.avl_node.right == &n2.node.avl_node);
	BOOST_REQUIRE(!n2.node.avl_node.left);
	BOOST_REQUIRE(!n2.node.avl_node.right);
	BOOST_REQUIRE(n4.node.avl_node.left == &n5.node.avl_node);
	BOOST_REQUIRE(n4.node.avl_node.right == &n3.node.avl_node);
	BOOST_REQUIRE(!n5.node.avl_node.left);
	BOOST_REQUIRE(!n5.node.avl_node.right);
	BOOST_REQUIRE(!n3.node.avl_node.left);
	BOOST_REQUIRE(!n3.node.avl_node.right);

	// triggers a LEFT-RIGHT rotation
	interval_tree_test_insert(&t, &n6);
	BOOST_REQUIRE(n1.node.avl_node.left == &n6.node.avl_node);
	BOOST_REQUIRE(n1.node.avl_node.right == &n2.node.avl_node);
	BOOST_REQUIRE(!n2.node.avl_node.left);
	BOOST_REQUIRE(!n2.node.avl_node.right);
	BOOST_REQUIRE(n3.node.avl_node.left == &n4.node.avl_node);
	BOOST_REQUIRE(n3.node.avl_node.right == &n1.node.avl_node);
	BOOST_REQUIRE(n4.node.avl_node.left == &n5.node.avl_node);
	BOOST_REQUIRE(!n4.node.avl_node.right);
	BOOST_REQUIRE(!n5.node.avl_node.left);
	BOOST_REQUIRE(!n5.node.avl_node.right);
	BOOST_REQUIRE(!n6.node.avl_node.left);
	BOOST_REQUIRE(!n6.node.avl_node.right);

	// triggers a LEFT rotation
	interval_tree_test_delete(&t, &n4);
	interval_tree_test_delete(&t, &n5);

	BOOST_REQUIRE(n1.node.avl_node.left == &n3.node.avl_node);
	BOOST_REQUIRE(n1.node.avl_node.right == &n2.node.avl_node);
	BOOST_REQUIRE(!n2.node.avl_node.left);
	BOOST_REQUIRE(!n2.node.avl_node.right);
	BOOST_REQUIRE(!n3.node.avl_node.left);
	BOOST_REQUIRE(n3.node.avl_node.right == &n6.node.avl_node);
	BOOST_REQUIRE(!n6.node.avl_node.left);
	BOOST_REQUIRE(!n6.node.avl_node.right);

	// triggers a LEFT-RIGHT rotation
	interval_tree_test_delete(&t, &n2);
	interval_tree_test_delete(&t, &n6);
	interval_tree_test_delete(&t, &n1);
	interval_tree_test_insert(&t, &n1);
	interval_tree_test_insert(&t, &n6);

	BOOST_REQUIRE(!n1.node.avl_node.left);
	BOOST_REQUIRE(!n1.node.avl_node.right);
	BOOST_REQUIRE(!n3.node.avl_node.left);
	BOOST_REQUIRE(!n3.node.avl_node.right);
	BOOST_REQUIRE(n6.node.avl_node.left == &n3.node.avl_node);
	BOOST_REQUIRE(n6.node.avl_node.right == &n1.node.avl_node);
}


// Trivial overlap test.
// We build a tree with one node and check if we indeed can satisfy the 6
// possibles cases

BOOST_AUTO_TEST_CASE(test_overlap_1)
{

#define LOW_    100
#define HIGH_   300

	struct interval_tree t;
	struct test n1;
	struct test *n2 = NULL;

	interval_tree_test_init_tree(&t);
	interval_tree_test_init_node(&n1);
	n1.foo = LOW_;
	n1.bar = HIGH_;
	interval_tree_test_insert(&t, &n1);

	// Overlaping
	n2 = interval_tree_test_find(&t, LOW_+12, HIGH_-13);
	BOOST_REQUIRE(n2);

	n2 = interval_tree_test_find(&t, LOW_-7, HIGH_-21);
	BOOST_REQUIRE(n2);

	n2 = interval_tree_test_find(&t, LOW_+1, HIGH_+12);
	BOOST_REQUIRE(n2);

	n2 = interval_tree_test_find(&t, LOW_-100, HIGH_+100);
	BOOST_REQUIRE(n2);

	// Non overlaping
	n2 = interval_tree_test_find(&t, HIGH_+100, HIGH_+300);
	BOOST_REQUIRE(!n2);

	n2 = interval_tree_test_find(&t, LOW_-100, LOW_-30);
	BOOST_REQUIRE(!n2);
}

BOOST_AUTO_TEST_CASE(test_overlap_2)
{
	struct interval_tree t;

	struct test n1;
	struct test n2;
	struct test n3;
	struct test n4;
	struct test n5;
	struct test *n6;

	interval_tree_test_init_tree(&t);
	interval_tree_test_init_node(&n1);
	interval_tree_test_init_node(&n2);
	interval_tree_test_init_node(&n3);
	interval_tree_test_init_node(&n4);
	interval_tree_test_init_node(&n5);

	n1.foo = 10;
	n1.bar = 13;

	n2.foo = 1;
	n2.bar = 6;

	n3.foo = 19;
	n3.bar = 155;

	n4.foo = 888;
	n4.bar = 10299;

	n5.foo = 999;
	n5.bar = 10200;

	interval_tree_test_insert(&t, &n1);
	interval_tree_test_insert(&t, &n2);
	interval_tree_test_insert(&t, &n3);
	interval_tree_test_insert(&t, &n4);
	interval_tree_test_insert(&t, &n5);

	// [20,150] overl. with [19,155]
	n6 = interval_tree_test_find(&t, 20, 150);
	BOOST_REQUIRE(!n6);

	// [17,20] overl. with [19,155]
	n6 = interval_tree_test_find(&t, 17, 20);
	BOOST_REQUIRE(n6);

	interval_tree_test_delete(&t, &n3);

	n6 = interval_tree_test_find(&t, 20, 150);
	BOOST_REQUIRE(!n6);

	n6 = interval_tree_test_find(&t, 17, 20);
	BOOST_REQUIRE(!n6);

	// [10199,12000] overl. with [999,10200]
	n6 = interval_tree_test_find(&t, 10199, 12000);
	BOOST_REQUIRE(n6);

	// [0,7] overl. with [1,6]
	n6 = interval_tree_test_find(&t, 0, 7);
	BOOST_REQUIRE(n6);

	interval_tree_test_delete(&t, &n4);
	interval_tree_test_delete(&t, &n5);
	interval_tree_test_delete(&t, &n2);

	n6 = interval_tree_test_find(&t, 10199, 12000);
	BOOST_REQUIRE(!n6);

	n6 = interval_tree_test_find(&t, 0, 7);
	BOOST_REQUIRE(!n6);
}

BOOST_AUTO_TEST_CASE(test_iterator)
{
	struct interval_tree t;

	struct test n1;
	struct test n2;
	struct test n3;
	struct test n4;
	struct test n5;
	struct test *n6;
	int i = 0;

	interval_tree_test_init_tree(&t);
	interval_tree_test_init_node(&n1);
	interval_tree_test_init_node(&n2);
	interval_tree_test_init_node(&n3);
	interval_tree_test_init_node(&n4);
	interval_tree_test_init_node(&n5);

	n1.foo = 10;
	n1.bar = 18;

	n2.foo = 13;
	n2.bar = 14;

	n3.foo = 13;
	n3.bar = 100;

	n4.foo = 1;
	n4.bar = 9;

	n5.foo = 1;
	n5.bar = 30;

	interval_tree_test_insert(&t, &n1);
	interval_tree_test_insert(&t, &n2);
	interval_tree_test_insert(&t, &n3);
	interval_tree_test_insert(&t, &n4);
	interval_tree_test_insert(&t, &n5);

	i=0;
	n6 = interval_tree_test_find_start(&t, 1, 8);
	while(n6 && i < 10) {
		if (i == 0 && n6 != &n4)
			BOOST_ERROR("i == 0 && n6 != &n4");
		if (i == 1 && n6 != &n5)
			BOOST_ERROR("i == 1 && n6 != &n5");
		if (i == 2)
			BOOST_ERROR("i == 2");

		n6 = interval_tree_test_find_next();
		i++;
	}

	i = 0;
	n6 = interval_tree_test_find_start(&t, 100, 140);

	while (n6 && i<10) {
		if (i == 0 && n6 != &n3)
			BOOST_ERROR("i == 0 && n6 != &n3");
		if (i == 1)
			BOOST_ERROR("i == 1");

		n6 = interval_tree_test_find_next();
		i++;
	}

	i = 0;
	n6 = interval_tree_test_find_start(&t, 18, 19);
	while (n6 && i<10) {
		if (i == 0 && n6 != &n5)
			BOOST_ERROR("i == 0 && n6 != &n5");
		if (i == 1 && n6 != &n1)
			BOOST_ERROR("i == 1 && n6 != &n1");
		if (i == 2 && n6 != &n3)
			BOOST_ERROR("i == 2 && n6 != &n3");
		if (i == 3)
			BOOST_ERROR("i == 3");

		n6 = interval_tree_test_find_next();
		i++;
	}
}

// Check if we can find an intervalle using the API and a single address
BOOST_AUTO_TEST_CASE(test_single_addr)
{
	struct interval_tree t;

	struct test n1;
	struct test n2;
	struct test n3;
	struct test n4;
	struct test n5;
	struct test *n6;

	interval_tree_test_init_tree(&t);
	interval_tree_test_init_node(&n1);
	interval_tree_test_init_node(&n2);
	interval_tree_test_init_node(&n3);
	interval_tree_test_init_node(&n4);
	interval_tree_test_init_node(&n5);

	n1.foo = 10;
	n1.bar = 18;

	n2.foo = 13;
	n2.bar = 14;

	n3.foo = 13;
	n3.bar = 100;

	n4.foo = 1;
	n4.bar = 9;

	n5.foo = 1;
	n5.bar = 30;

	interval_tree_test_insert(&t, &n1);
	interval_tree_test_insert(&t, &n2);
	interval_tree_test_insert(&t, &n3);
	interval_tree_test_insert(&t, &n4);
	interval_tree_test_insert(&t, &n5);

	// Must match with [13,14]
	n6 = interval_tree_test_find(&t, 13, 13);
	BOOST_REQUIRE(n6);

	// Must match with [1,30]
	n6 = interval_tree_test_find(&t, 30, 30);
	BOOST_REQUIRE(n6);
}
