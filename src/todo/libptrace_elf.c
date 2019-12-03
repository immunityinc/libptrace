/* libptrace, a process tracing and manipulation library.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
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
 * libptrace_elf.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <link.h>
#include "libptrace.h"

#define STACK_SIZE	0x10000

/** Retrieve the first entry of the ELF link_map linked list of a process.
 *
 * Retrieves the head of the link_map linked list of a process conforming
 * to the SysV gABI specification, which describes a loaded dynamic shared
 * object.
 * This is a SysV gABI specific function, and therefore it is not part of
 * the generic libptrace API.
 *
 * \param pctx Pointer to the ptrace_context of the traced thread.
 * \param map Pointer to the link_map structure which the first link_map
 *            entry of the remote process will be written to.
 *
 * \return 0 on success, -1 on failure.
 */
int
ptrace_elf_get_link_map_head(struct ptrace_context *pctx,
                             struct link_map *map)
{
	int ret;
	Elf32_Dyn dyn;
	Elf32_Ehdr ehdr;
	Elf32_Phdr phdr;
	unsigned int i = 0;
	void *link_map_ptr;
	struct link_map link_map;

	/* Read out the ELF header. */
	ret = ptrace_read(pctx, &ehdr, ELF_HEADER_BASE, sizeof(ehdr));
	if (ret == -1)
		return -1;


	/* We're looking for the PT_DYNAMIC section in the program header
	 * table.
	 *
	 * XXX: sanity check we don't read outside ELF map area etc.
	 */
	do {
		ret = ptrace_read(pctx, &phdr,
		                  ELF_HEADER_BASE + ehdr.e_phoff +
				  i++ * sizeof(phdr), sizeof(phdr));
		if (ret == -1)
			return -1;
	} while (phdr.p_type != PT_DYNAMIC);

	/* Now try to locate the _GLOBAL_OFFSET_TABLE. */
	i = 0;
	do {
		ret = ptrace_read(pctx, &dyn, phdr.p_vaddr +
		                  i++ * sizeof(dyn), sizeof(dyn));
		if (ret == -1)
			return -1;
	} while (dyn.d_tag != DT_PLTGOT);

	/* Read out the link_map pointer, which is the second GOT entry. */
	ret = ptrace_read(pctx, &link_map_ptr, dyn.d_un.d_ptr + 4,
	                  sizeof(link_map_ptr));
	if (ret == -1)
		return -1;

	/* And read out the link_map structure itself. */
	ret = ptrace_read(pctx, &link_map, link_map_ptr, sizeof(link_map));
	if (ret == -1)
		return -1;

	/* We're succesful, so we copy out the link_map struct we found. */
	memcpy(map, &link_map, sizeof(link_map));

	return 0;
}

/** Retrieve the next entry of a link_map linked list entry of a process.
 *
 * Retrieves the next entry of the link_map linked list of a process conforming
 * to the SysV gABI specification, which describes a loaded dynamic shared
 * object.
 * This is a SysV gABI specific function, and therefore it is not part of
 * the generic libptrace API.
 *
 * \param pctx Pointer to the ptrace_context of the traced thread.
 * \param map Pointer to the link_map structure in the remote process which
 *            is used to locate the next link_map entry with.
 * \param next Pointer to the link_map structure which the next link_map
 *             entry of the remote process will be written to.
 *
 * \return 0 on success, -1 on failure.
 */
int
ptrace_elf_get_link_map_next(struct ptrace_context *pctx,
                             struct link_map *map, struct link_map *next)
{
	return ptrace_read(pctx, next, map->l_next, sizeof(*next));
}

/** Retrieve the address of a specific ELF dynamic section.
 *
 * Retrieves the address of a specific SysV gABI dynamic section of a
 * process, given an optional link_map description of a loaded shared
 * object.
 * This is a SysV gABI specific function, and therefore it is not part of
 * the generic libptrace API.
 *
 * \param pctx Pointer to the ptrace_context of the traced thread.
 * \param map Pointer to the link_map describing the loaded shared object
 *            to retrieve the symbol table for.  When set to NULL, the
 *            symbol table of the process itself is returned.
 * \param tag Dynamic entry type of which the address will be returned.
 *
 * \return The dynamic entry address on success, NULL on failure.
 */
void *ptrace_elf_get_dynamic_entry(struct ptrace_context *pctx,
                                   struct link_map *map, Elf32_Sword tag)
{
	Elf32_Dyn dyn;
	Elf32_Dyn *dyn_ptr;

	if (map == NULL) {
		/* TODO */
		return -1;
	}

	dyn_ptr = map->l_ld;
	do {
		if ( ptrace_read(pctx, &dyn, dyn_ptr++, sizeof(dyn)) == -1 )
			return -1;

		if (dyn.d_tag == tag)
			return (void *) dyn.d_un.d_ptr;
	} while (dyn.d_tag != DT_NULL);

	return NULL;
}

/** Retrieve the address of the ELF symbol table of a loaded shared object.
 *
 * Retrieves the address of the SysV gABI symbol table of a process, given
 * an optional link_map description of a loaded shared object.
 * This is a SysV gABI specific function, and therefore it is not part of
 * the generic libptrace API.
 *
 * \param pctx Pointer to the ptrace_context of the traced thread.
 * \param map Pointer to the link_map describing the loaded shared object
 *            to retrieve the symbol table for.  When set to NULL, the
 *            symbol table of the process itself is returned.
 *
 * \return The symbol table address on success, NULL on failure.
 */
void *ptrace_elf_get_symtab(struct ptrace_context *pctx, struct link_map *map)
{
	return ptrace_elf_get_dynamic_entry(pctx, map, DT_SYMTAB);
}

/** Retrieve the address of the ELF string table of a loaded shared object.
 *
 * Retrieves the address of the SysV gABI string table of a process, given
 * an optional link_map description of a loaded shared object.
 * This is a SysV gABI specific function, and therefore it is not part of
 * the generic libptrace API.
 *
 * \param pctx Pointer to the ptrace_context of the traced thread.
 * \param map Pointer to the link_map describing the loaded shared object
 *            to retrieve the string table for.  When set to NULL, the
 *            string table of the process itself is returned.
 *
 * \return The string table address on success, NULL on failure.
 */
void *ptrace_elf_get_strtab(struct ptrace_context *pctx, struct link_map *map)
{
	return ptrace_elf_get_dynamic_entry(pctx, map, DT_STRTAB);
}

/** Retrieve the address of the ELF hash table of a loaded shared object.
 *
 * Retrieves the address of the SysV gABI hash table of a process, given
 * an optional link_map description of a loaded shared object.
 * This is a SysV gABI specific function, and therefore it is not part of
 * the generic libptrace API.
 *
 * \param pctx Pointer to the ptrace_context of the traced thread.
 * \param map Pointer to the link_map describing the loaded shared object
 *            to retrieve the string table for.  When set to NULL, the
 *            string table of the process itself is returned.
 *
 * \return The hash table address on success, NULL on failure.
 */
void *ptrace_elf_get_hash(struct ptrace_context *pctx, struct link_map *map)
{
	return ptrace_elf_get_dynamic_entry(pctx, map, DT_HASH);
}

/** Retrieve the number of chains in an ELF hash table.
 *
 * Retrieves the number of chains of an SysV gABI hash table of a process,
 * given an optional link_map description of a loaded shared object.
 * This is a SysV gABI specific function, and therefore it is not part of
 * the generic libptrace API.
 *
 * \param pctx Pointer to the ptrace_context of the traced thread.
 * \param map Pointer to the link_map describing the loaded shared object
 *            to retrieve the string table for.  When set to NULL, the
 *            string table of the process itself is returned.
 * \param chains Pointer to an Elf32_Word which the number of chains will
 *               be written to.
 *
 * \return 0 on success, -1 on failure.
 */
int
ptrace_elf_get_hash_chains(struct ptrace_context *pctx,
                           struct link_map *map, Elf32_Word *chains)
{
	int ret;
	void *hash;
	Elf32_Word __chains;

	hash = ptrace_elf_get_hash(pctx, map);
	if (hash == NULL)
		return -1;

	ret = ptrace_read(pctx, &__chains, hash + sizeof(Elf32_Word),
	                  sizeof(Elf32_Word));
	if (ret == -1)
		return -1;

	*chains = __chains;
	return 0;
}

/** Retrieve the address of an ELF symbol in a loaded shared object.
 *
 * Retrieves the address of a SysV gABI symbol of a loaded shared object
 * in a remote process, given an optional link_map description of a loaded
 * shared object.
 * This is a SysV gABI specific function, and therefore it is not part of
 * the generic libptrace API.
 *
 * \param pctx Pointer to the ptrace_context of the traced thread.
 * \param map Pointer to the link_map describing the loaded shared object
 *            to retrieve the symbol address for.  When set to NULL, all
 *            loaded shared objects of the process are searched for the
 *            symbol.
 *
 * \return The address of the symbol on success, NULL on failure.
 */
/* XXX: use ELF hash table for this later. */
void *
ptrace_elf_get_symbol_addr(struct ptrace_context *pctx,
                           struct link_map *map, const char *symbol)
{
	int ret;
	void *strtab;
	Elf32_Sym sym;
	char *__symbol;
	Elf32_Sym *symtab;
	uint32_t i, hash_chains;

	/* In case the link_map is NULL, we search all loaded shared
	 * objects for the given symbol.
	 */
	if (map == NULL) {
		void *ptr;
		struct link_map map;

		/* Get the list head, and examine it. */
		if ( ptrace_elf_get_link_map_head(pctx, &map) == -1 )
			return NULL;

		ptr = ptrace_elf_get_symbol_addr(pctx, &map, symbol);
		if (ptr != NULL)
			return ptr;

		/* Traverse the rest of the list. */
		while (map.l_next != NULL) {
			ret = ptrace_elf_get_link_map_next(pctx, &map, &map);
			if (ret == -1)
				return NULL;

			ptr = ptrace_elf_get_symbol_addr(pctx, &map, symbol);
			if (ptr != NULL)
				return ptr;
		}

		return NULL;
	}

	symtab = ptrace_elf_get_symtab(pctx, map);
	if (symtab == NULL)
		return NULL;

	strtab = ptrace_elf_get_strtab(pctx, map);
	if (strtab == NULL)
		return NULL;

	/* The number of hash chains is equal to the number of entries
	 * in the symbol table.
	 */
	if ( ptrace_elf_get_hash_chains(pctx, map, &hash_chains) == -1 )
		return NULL;

	__symbol = malloc(strlen(symbol) + 1);
	if (__symbol == NULL)
		return NULL;

	/* The first SYMTAB entry is reserved and we don't care for it.
	 * Hence we start symbol table traversal from index 1.
	 */
	for (i = 1; i < hash_chains; i++) {
		ret = ptrace_read(pctx, &sym, symtab + i, sizeof(sym));
		if (ret == -1)
			goto out;

		ret = ptrace_read_string(pctx, __symbol, strlen(symbol) + 1,
		                         strtab + sym.st_name);
		if (ret == -1)
			goto out;

		if ( !strcmp(symbol, __symbol) ) {
			free(__symbol);
			return (void *)(map->l_addr + sym.st_value);
		}
	}

out:
	free(__symbol);
	return NULL;
}

void *
ptrace_dlopen(struct ptrace_context *pctx, const char *libname, int flags)
{
	void *__libname;
	void *retval = NULL;
	void *__libc_dlopen_mode;
	struct ptrace_altstack stack, old_stack;

	__libc_dlopen_mode =
		ptrace_elf_get_symbol_addr(pctx, NULL, "__libc_dlopen_mode");
	if (__libc_dlopen_mode == NULL)
		goto out;

	if ( ptrace_altstack_init(pctx, &stack, STACK_SIZE) == -1 )
		goto out;

	if ( ptrace_altstack_switch(pctx, &stack, &old_stack) == -1 )
		goto out_altstack_destroy;

	__libname = ptrace_malloc(pctx, strlen(libname) + 1);
	if (__libname == NULL)
		goto out_altstack_switch;

	if ( ptrace_write(pctx, __libname, libname, strlen(libname) + 1) == -1 )
		goto out_libname_free;

	/* Open the library using the glibc internal __RTLD_DLOPEN flag which
	 * emulates dlopen() like behaviour.  No clue what it does exactly, but
	 * things crash without it.
	 */
	flags |= __RTLD_DLOPEN;

	if ( ptrace_push32(pctx, flags) == -1 ||
	     ptrace_push32(pctx, (uint32_t) __libname) == -1 )
		goto out_libname_free;

	ptrace_call_function(pctx, __libc_dlopen_mode, (int *) &retval);

out_libname_free:
	if ( ptrace_free(pctx, __libname) == -1 )
		return NULL;
out_altstack_switch:
	if ( ptrace_altstack_switch(pctx, &old_stack, NULL) == -1 )
		return NULL;
out_altstack_destroy:
	if ( ptrace_altstack_destroy(pctx, &stack) == -1 )
		return NULL;
out:
	return retval;
}

void *
ptrace_dlsym(struct ptrace_context *pctx, void *handle, const char *symbol)
{
	void *__symbol;
	void *__libc_dlsym;
	void *retval = NULL;
	struct ptrace_altstack stack, old_stack;

	__libc_dlsym =
		ptrace_elf_get_symbol_addr(pctx, NULL, "__libc_dlsym");
	if (__libc_dlsym == NULL)
		goto out;

	if ( ptrace_altstack_init(pctx, &stack, STACK_SIZE) == -1 )
		goto out;

	if ( ptrace_altstack_switch(pctx, &stack, &old_stack) == -1 )
		goto out_altstack_destroy;

	__symbol = ptrace_malloc(pctx, strlen(symbol) + 1);
	if (__symbol == NULL)
		goto out_altstack_switch;

	if ( ptrace_write(pctx, __symbol, symbol, strlen(symbol) + 1) == -1 )
		goto out_libname_free;

	if ( ptrace_push32(pctx, (uint32_t) __symbol) == -1 ||
	     ptrace_push32(pctx, (uint32_t) handle) == -1 )
		goto out_libname_free;

	ptrace_call_function(pctx, __libc_dlsym, (int *) &retval);

out_libname_free:
	if ( ptrace_free(pctx, __symbol) == -1 )
		return NULL;
out_altstack_switch:
	if ( ptrace_altstack_switch(pctx, &old_stack, NULL) == -1 )
		return NULL;
out_altstack_destroy:
	if ( ptrace_altstack_destroy(pctx, &stack) == -1 )
		return NULL;
out:
	return retval;
}

int
ptrace_dlclose(struct ptrace_context *pctx, void *handle)
{
	int retval = -1;
	void *__libc_dlclose;
	struct ptrace_altstack stack, old_stack;

	__libc_dlclose =
		ptrace_elf_get_symbol_addr(pctx, NULL, "__libc_dlclose");
	if (__libc_dlclose == NULL)
		goto out;

	if ( ptrace_altstack_init(pctx, &stack, STACK_SIZE) == -1 )
		goto out;

	if ( ptrace_altstack_switch(pctx, &stack, &old_stack) == -1 )
		goto out_altstack_destroy;

	if ( ptrace_push32(pctx, (uint32_t) handle) == -1)
		goto out_altstack_switch;

	ptrace_call_function(pctx, __libc_dlclose, (int *) &retval);

out_altstack_switch:
	if ( ptrace_altstack_switch(pctx, &old_stack, NULL) == -1 )
		return -1;
out_altstack_destroy:
	if ( ptrace_altstack_destroy(pctx, &stack) == -1 )
		return -1;
out:
	return retval;
}

ptrace_library_handle_t
ptrace_library_load(struct ptrace_context *pctx, const char *libname)
{
	int ret;
	char *pathname;
	char *cwd = NULL;
	const char *basename;
	ptrace_library_handle_t handle = NULL;

	/* Find the basename of the library, in case libname is a full
	 * pathname.
	 */
	if ( (basename = strrchr(libname, '/')) == NULL ) {
		if ( (cwd = getcwd(NULL, 0)) == NULL )
			return NULL;
		basename = libname;
	} else {
		basename++;
	}

	/* Construct the full pathname of the shared library object. */
	ret = asprintf(&pathname, "%s%s%s%s",
		               cwd ? cwd : "", cwd ? "/" : "",  libname,
			       strrchr(basename, '.') == NULL ? ".so" : "");
	if (ret == -1)
		return NULL;

	handle = ptrace_dlopen(pctx, pathname, RTLD_NOW);

	free(pathname);
	if (cwd != NULL)
		free(cwd);
	return handle;
}

int
ptrace_library_unload(struct ptrace_context *pctx,
                      ptrace_library_handle_t handle)
{
	return ptrace_dlclose(pctx, handle);
}

ptrace_function_ptr_t
ptrace_library_get_function_addr(struct ptrace_context *pctx,
                                 ptrace_library_handle_t handle,
                                 const char *symbol)
{
	return ptrace_dlsym(pctx, handle, symbol);
}
