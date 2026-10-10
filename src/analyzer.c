#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long virtual_to_offset(Elf64_Phdr *phdrs, int count, Elf64_Addr vaddr)
{
	int i;

	for (i = 0; i < count; i++)
	{
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		if (vaddr >= phdrs[i].p_vaddr &&
			vaddr < phdrs[i].p_vaddr + phdrs[i].p_filesz)
		{
			return phdrs[i].p_offset +
				(vaddr - phdrs[i].p_vaddr);
		}
	}

	return -1;
}

void print_load_segment(Elf64_Phdr *phdr, int index)
{
	printf("\nPT_LOAD %d\n", index);
	printf("  Offset : 0x%lx\n", phdr->p_offset);
	printf("  VAddr  : 0x%lx\n", phdr->p_vaddr);
	printf("  FileSz : 0x%lx\n", phdr->p_filesz);
	printf("  MemSz  : 0x%lx\n", phdr->p_memsz);
	printf("  Flags  : ");

	if (phdr->p_flags & PF_R)
		printf("R");
	if (phdr->p_flags & PF_W)
		printf("W");
	if (phdr->p_flags & PF_X)
		printf("X");

	printf("\n");
	printf("  File end : 0x%lx\n",
		phdr->p_offset + phdr->p_filesz);
	printf("  VA end   : 0x%lx\n",
		phdr->p_vaddr + phdr->p_memsz);

	if (phdr->p_flags & PF_X)
		printf("  -> Segment executable\n");
}

void print_sections(FILE *file, Elf64_Ehdr *header)
{
	Elf64_Shdr *sections;
	Elf64_Shdr *string_section;
	char *strings;
	int i;

	sections = malloc(sizeof(Elf64_Shdr) * header->e_shnum);
	if (sections == NULL)
	{
		printf("Erreur malloc sections\n");
		return;
	}

	if (fseek(file, header->e_shoff, SEEK_SET) != 0)
	{
		printf("Erreur de positionnement sections\n");
		free(sections);
		return;
	}

	if (fread(sections, sizeof(Elf64_Shdr),
		header->e_shnum, file) != header->e_shnum)
	{
		printf("Erreur de lecture des sections\n");
		free(sections);
		return;
	}

	string_section = &sections[header->e_shstrndx];

	strings = malloc(string_section->sh_size);
	if (strings == NULL)
	{
		printf("Erreur malloc noms sections\n");
		free(sections);
		return;
	}

	if (fseek(file, string_section->sh_offset, SEEK_SET) != 0)
	{
		printf("Erreur de positionnement noms sections\n");
		free(strings);
		free(sections);
		return;
	}

	if (fread(strings, 1, string_section->sh_size, file)
		!= string_section->sh_size)
	{
		printf("Erreur de lecture noms sections\n");
		free(strings);
		free(sections);
		return;
	}

	printf("\nSections:\n");

	for (i = 0; i < header->e_shnum; i++)
	{
		printf("\n[%d] %s\n",
			i,
			strings + sections[i].sh_name);

		printf("  Type   : 0x%x\n", sections[i].sh_type);
		printf("  Offset : 0x%lx\n", sections[i].sh_offset);
		printf("  Addr   : 0x%lx\n", sections[i].sh_addr);
		printf("  Size   : 0x%lx\n", sections[i].sh_size);
		printf("  Flags  : ");

		if (sections[i].sh_flags & SHF_ALLOC)
			printf("A");
		if (sections[i].sh_flags & SHF_WRITE)
			printf("W");
		if (sections[i].sh_flags & SHF_EXECINSTR)
			printf("X");

		printf("\n");
	}

	free(strings);
	free(sections);
}

int main(int argc, char **argv)
{
	FILE *file;
	Elf64_Ehdr header;
	Elf64_Phdr *phdrs;
	int i;
	long offset;

	if (argc != 2)
	{
		printf("Usage: %s <elf>\n", argv[0]);
		return 1;
	}

	file = fopen(argv[1], "rb");
	if (file == NULL)
	{
		perror("fopen");
		return 1;
	}

	if (fread(&header, sizeof(header), 1, file) != 1)
	{
		printf("Erreur de lecture\n");
		fclose(file);
		return 1;
	}

	if (header.e_ident[EI_MAG0] != ELFMAG0 ||
		header.e_ident[EI_MAG1] != ELFMAG1 ||
		header.e_ident[EI_MAG2] != ELFMAG2 ||
		header.e_ident[EI_MAG3] != ELFMAG3)
	{
		printf("Ce fichier n'est pas un ELF\n");
		fclose(file);
		return 1;
	}

	printf("ELF valide\n");
	printf("Entry point : 0x%lx\n", header.e_entry);
	printf("Program headers : %u\n", header.e_phnum);
	printf("Section headers : %u\n", header.e_shnum);

	phdrs = malloc(sizeof(Elf64_Phdr) * header.e_phnum);
	if (phdrs == NULL)
	{
		printf("Erreur malloc\n");
		fclose(file);
		return 1;
	}

	if (fseek(file, header.e_phoff, SEEK_SET) != 0)
	{
		printf("Erreur de positionnement\n");
		free(phdrs);
		fclose(file);
		return 1;
	}

	if (fread(phdrs, sizeof(Elf64_Phdr),
		header.e_phnum, file) != header.e_phnum)
	{
		printf("Erreur de lecture des program headers\n");
		free(phdrs);
		fclose(file);
		return 1;
	}

	printf("\nPT_LOAD:\n");

	for (i = 0; i < header.e_phnum; i++)
	{
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		print_load_segment(&phdrs[i], i);
	}

	printf("\nEntry point:\n");
	printf("  VA     : 0x%lx\n", header.e_entry);

	offset = virtual_to_offset(
		phdrs,
		header.e_phnum,
		header.e_entry
	);

	if (offset >= 0)
		printf("  Offset : 0x%lx\n", offset);
	else
		printf("  Offset : introuvable\n");

	print_sections(file, &header);

	free(phdrs);
	fclose(file);

	return 0;
}
