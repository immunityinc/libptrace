/* libptrace, a process tracing and manipulation library.
 *
 * Dedicated to Yuzuyu Arielle Huizer
 *
 * Copyright (C) 2006-2019 Ronald Huizer <rhuizer@hexpedition.com>
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
 * libptrace_elf.h
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#ifndef __LIBPTRACE_ELF_H

#include <elf.h>
#include <link.h>

#define __RTLD_DLOPEN 0x80000000

int ptrace_elf_get_link_map_head(struct ptrace_context *pctx,
                                 struct link_map *map);
int ptrace_elf_get_link_map_next(struct ptrace_context *pctx,
                                 struct link_map *map,
				 struct link_map *next);
void *ptrace_elf_get_dynamic_entry(struct ptrace_context *pctx,
                                   struct link_map *map, Elf32_Sword tag);
void *ptrace_elf_get_symtab(struct ptrace_context *pctx,
                            struct link_map *map);
void *ptrace_elf_get_strtab(struct ptrace_context *pctx,
                            struct link_map *map);
void *ptrace_elf_get_hash(struct ptrace_context *pctx,
                          struct link_map *map);
int ptrace_elf_get_hash_chains(struct ptrace_context *pctx,
                               struct link_map *map, Elf32_Word *chains);
void *ptrace_elf_get_symbol_addr(struct ptrace_context *pctx,
                                 struct link_map *map, const char *symbol);
void *ptrace_dlopen(struct ptrace_context *pctx, const char *libname,
                    int flags);
void * ptrace_dlsym(struct ptrace_context *pctx, void *handle,
                    const char *symbol);
int ptrace_dlclose(struct ptrace_context *pctx, void *handle);
//ptrace_function_ptr_t
//ptrace_library_get_function_addr(struct ptrace_context *pctx,
//                                 ptrace_library_handle_t handle,
//                                 const char *symbol);
#endif	/* __LIBPTRACE_ELF_H */
