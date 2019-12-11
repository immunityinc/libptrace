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
 * mmap.c
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Author: Ronald Huizer <ronald@immunityinc.com>
 * Author: Roderick Asselineau <roderick@immunityinc.com>
 *
 */
#include <stdio.h>
#include <inttypes.h>
#include <libptrace/libptrace.h>

void printf_node(void *n_)
{
        struct pt_mmap_area *n = (struct pt_mmap_area *)n_;
        struct avl_node *p;
        struct interval_tree_node *p_;
        struct pt_mmap_area *p__;
        
        if (!n_)
                return;
                
        printf("NODE [0x%.8x,0x%.8x]\n", n->_start, n->_end, &n->node.avl_node);

        if (n->node.avl_node.parent) {
                p   = n->node.avl_node.parent;
                p_  = container_of(p, struct interval_tree_node, avl_node);
                p__ = container_of(p_, struct pt_mmap_area, node);
                printf("\t-> parent [0x%.8x,0x%.8x]\n", p__->_start, p__->_end);
        }

        if(n->node.avl_node.left) {
                p   = n->node.avl_node.left;
                p_  = container_of(p, struct interval_tree_node, avl_node);
                p__ = container_of(p_, struct pt_mmap_area, node);
                printf("\t-> left [0x%.8x,0x%.8x]\n", p__->_start, p__->_end);
        }

        if (n->node.avl_node.right) {
                p   = n->node.avl_node.right;
                p_  = container_of(p, struct interval_tree_node, avl_node);
                p__ = container_of(p_, struct pt_mmap_area, node);
                printf("\t-> right [0x%.8x,0x%.8x]\n", p__->_start, p__->_end);
        }

        printf("\t-> max %.8x\n", n->node.max);
}       

int test_process()
{
        struct pt_process process;
        struct pt_mmap_area *area;
        int pid, ret;

        pt_process_init(&process);

        if (pt_process_execl(&process, "C:\\Windows\\notepad.exe", NULL) == -1) {
	        fprintf(stderr, "pt_execl() failed.\n");
	        return 0;
        }

        if (pt_mmap_load(&process) == -1) {
	        fprintf(stderr, "pt_mmap_load() failed.\n");
	        return 0;
        }


        pt_mmap_for_each_area(&process.mmap, area) {
	        printf("%.8x-%.8x ", area->_start, area->_end);

	        printf("%c%c%c\n",
		        (area->flags & PT_VMA_PROT_READ)  ? 'r' : '-',
		        (area->flags & PT_VMA_PROT_WRITE) ? 'w' : '-',
		        (area->flags & PT_VMA_PROT_EXEC)  ? 'x' : '-');
        }

        return 1;
}

int test_find(void)
{
        struct pt_mmap tree;
	struct pt_mmap_area *a1,*a2,*a3,*a4,*a;
	int pid, ret;
        int i = 0;
	
	pt_mmap_init(&tree);
	
	a1 = pt_mmap_area_new();
        a2 = pt_mmap_area_new();
        a3 = pt_mmap_area_new();
        a4 = pt_mmap_area_new();
        
        pt_mmap_area_init(a1);
        pt_mmap_area_init(a2);
        pt_mmap_area_init(a3);
        pt_mmap_area_init(a4);
        
        a1->_start =1;
        a1->_end =3;

        a2->_start =2;
        a2->_end =4;

        a3->_start =5;
        a3->_end =7;
        
        a4->_start =3;
        a4->_end = 19;
        
        pt_mmap_add_area(&tree, a1);
        pt_mmap_add_area(&tree, a2);
        pt_mmap_add_area(&tree, a3);
        pt_mmap_add_area(&tree, a4);
        
        // There should be 2 entries overlapping with 2
        a = pt_mmap_find_all_area_from_address_start(&tree, 2);
        while(a)
        {
                i++;
                a = pt_mmap_find_all_area_from_address_next();
        }
        
        if(i!=2)
                return 0;
                
        // If there is no corruption we should be able to remove the nodes
        // without a problem.
        
        pt_mmap_area_delete(&tree, a2);
        pt_mmap_area_delete(&tree, a4);
        pt_mmap_area_delete(&tree, a1);
        pt_mmap_area_delete(&tree, a3);
        return 1;
}


int main(int argc, char **argv)
{

        if(!test_find())
                exit(EXIT_FAILURE);
                
        if(!test_process())
                exit(EXIT_FAILURE);
                
        exit(EXIT_SUCCESS);
}
