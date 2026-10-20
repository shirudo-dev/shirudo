// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <gelf.h>
#include <stdbool.h>
#include <stdio.h>

#include <bpf/libbpf.h>

#include "util/loader.h"

static int symbols(const char *selection,
		   const struct shirudo_embedded_bpf *blob)
{
	Elf_Scn *section = NULL;
	Elf *elf;
	int rc = 0;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return 1;
	elf = elf_memory((char *)blob->data, blob->size);
	if (!elf)
		return 1;
	while ((section = elf_nextscn(elf, section))) {
		GElf_Shdr header;
		Elf_Data *data;
		size_t i;

		if (!gelf_getshdr(section, &header)) {
			rc = 1;
			break;
		}
		if (header.sh_type != SHT_SYMTAB)
			continue;
		data = elf_getdata(section, NULL);
		if (!data || !header.sh_entsize) {
			rc = 1;
			break;
		}
		for (i = 1; i < header.sh_size / header.sh_entsize; i++) {
			GElf_Sym symbol;
			const char *name;

			if (!gelf_getsym(data, i, &symbol)) {
				rc = 1;
				break;
			}
			if (symbol.st_shndx != SHN_UNDEF)
				continue;
			name = elf_strptr(elf, header.sh_link, symbol.st_name);
			if (!name) {
				rc = 1;
				break;
			}
			printf("extern %s %s\n", selection, name);
		}
	}
	elf_end(elf);
	return rc;
}

static int inspect(const char *selection,
		   const struct shirudo_embedded_bpf *blob)
{
	struct bpf_program *program;
	struct bpf_object *obj;
	struct bpf_map *map;

	obj = bpf_object__open_mem(blob->data, blob->size, NULL);
	if (!obj)
		return 1;
	printf("blob %s %s\n", selection, blob->name);
	bpf_object__for_each_program(program, obj)
		printf("program %s %s\n", selection,
		       bpf_program__name(program));
	bpf_object__for_each_map(map, obj)
		printf("map %s %s\n", selection, bpf_map__name(map));
	bpf_object__close(obj);
	return symbols(selection, blob);
}

int main(void)
{
	return inspect("ordinary-admission", bpf2_blob(false)) ||
	       inspect("image-admission", bpf2_blob(true)) ||
	       inspect("ordinary-seal", seal_blob(false)) ||
	       inspect("image-seal", seal_blob(true));
}
