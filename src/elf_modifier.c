#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int read_headers(FILE *file, Elf64_Ehdr *header, Elf64_Phdr **phdrs)
{
	if (fread(header, sizeof(*header), 1, file) != 1)
		return 0;

	if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0)
		return 0;

	*phdrs = malloc(sizeof(Elf64_Phdr) * header->e_phnum);
	if (*phdrs == NULL)
		return 0;

	if (fseek(file, header->e_phoff, SEEK_SET) != 0)
	{
		free(*phdrs);
		return 0;
	}

	if (fread(*phdrs, sizeof(Elf64_Phdr),
		header->e_phnum, file) != header->e_phnum)
	{
		free(*phdrs);
		return 0;
	}

	return 1;
}

long virtual_to_offset(Elf64_Phdr *phdrs, int count,
	Elf64_Addr vaddr)
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

void print_executable_segment(Elf64_Phdr *phdrs, int count)
{
	int i;

	for (i = 0; i < count; i++)
	{
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		if (!(phdrs[i].p_flags & PF_X))
			continue;

		printf("\nSegment executable\n");
		printf("  File start : 0x%lx\n", phdrs[i].p_offset);
		printf("  File end   : 0x%lx\n",
			phdrs[i].p_offset + phdrs[i].p_filesz);
		printf("  VA start   : 0x%lx\n", phdrs[i].p_vaddr);
		printf("  VA end     : 0x%lx\n",
			phdrs[i].p_vaddr + phdrs[i].p_filesz);
		printf("  File size  : 0x%lx\n", phdrs[i].p_filesz);

		return;
	}

	printf("Segment executable introuvable\n");
}

void print_segment_gaps(Elf64_Phdr *phdrs, int count)
{
	int i;
	int j;
	Elf64_Phdr *current;
	Elf64_Phdr *next;
	Elf64_Off current_end;
	Elf64_Off next_start;

	printf("\nEspaces entre les segments PT_LOAD\n");

	for (i = 0; i < count; i++)
	{
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		current = &phdrs[i];
		current_end = current->p_offset + current->p_filesz;
		next = NULL;

		for (j = 0; j < count; j++)
		{
			if (phdrs[j].p_type != PT_LOAD)
				continue;

			if (phdrs[j].p_offset <= current->p_offset)
				continue;

			if (next == NULL ||
				phdrs[j].p_offset < next->p_offset)
			{
				next = &phdrs[j];
			}
		}

		if (next == NULL)
			continue;

		next_start = next->p_offset;

		if (next_start > current_end)
		{
			printf("\nEntre PT_LOAD :\n");
			printf("  Fin actuel    : 0x%lx\n", current_end);
			printf("  Debut suivant : 0x%lx\n", next_start);
			printf("  Espace        : 0x%lx (%lu octets)\n",
				next_start - current_end,
				next_start - current_end);
		}
	}
}

int find_text(FILE *file, Elf64_Ehdr *header,
	Elf64_Addr *address, Elf64_Xword *size)
{
	Elf64_Shdr *sections;
	Elf64_Shdr string_section;
	char *strings;
	int i;

	sections = malloc(sizeof(Elf64_Shdr) * header->e_shnum);
	if (sections == NULL)
		return 0;

	if (fseek(file, header->e_shoff, SEEK_SET) != 0)
	{
		free(sections);
		return 0;
	}

	if (fread(sections, sizeof(Elf64_Shdr),
		header->e_shnum, file) != header->e_shnum)
	{
		free(sections);
		return 0;
	}

	string_section = sections[header->e_shstrndx];

	strings = malloc(string_section.sh_size);
	if (strings == NULL)
	{
		free(sections);
		return 0;
	}

	if (fseek(file, string_section.sh_offset, SEEK_SET) != 0)
	{
		free(strings);
		free(sections);
		return 0;
	}

	if (fread(strings, 1, string_section.sh_size, file)
		!= string_section.sh_size)
	{
		free(strings);
		free(sections);
		return 0;
	}

	for (i = 0; i < header->e_shnum; i++)
	{
		if (strcmp(strings + sections[i].sh_name, ".text") == 0)
		{
			*address = sections[i].sh_addr;
			*size = sections[i].sh_size;

			free(strings);
			free(sections);
			return 1;
		}
	}

	free(strings);
	free(sections);
	return 0;
}

void print_text_info(FILE *file, Elf64_Ehdr *header,
	Elf64_Phdr *phdrs, int count)
{
	Elf64_Addr text_address;
	Elf64_Xword text_size;
	long text_offset;
	int i;

	if (!find_text(file, header, &text_address, &text_size))
	{
		printf("\nSection .text introuvable\n");
		return;
	}

	text_offset = virtual_to_offset(
		phdrs,
		count,
		text_address
	);

	printf("\nSection .text\n");
	printf("  VA         : 0x%lx\n", text_address);
	printf("  Offset     : 0x%lx\n", text_offset);
	printf("  Size       : 0x%lx\n", text_size);
	printf("  VA end     : 0x%lx\n",
		text_address + text_size);
	printf("  Offset end : 0x%lx\n",
		text_offset + text_size);

	for (i = 0; i < count; i++)
	{
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		if (!(phdrs[i].p_flags & PF_X))
			continue;

		if (text_address >= phdrs[i].p_vaddr &&
			text_address < phdrs[i].p_vaddr + phdrs[i].p_filesz)
		{
			printf("  Segment    : PT_LOAD %d\n", i);
			break;
		}
	}
}

void print_text_remaining_space(FILE *file, Elf64_Ehdr *header,
	Elf64_Phdr *phdrs, int count)
{
	Elf64_Addr text_address;
	Elf64_Xword text_size;
	Elf64_Addr text_end;
	Elf64_Addr segment_end;
	int i;

	if (!find_text(file, header, &text_address, &text_size))
	{
		printf("\nSection .text introuvable\n");
		return;
	}

	text_end = text_address + text_size;

	for (i = 0; i < count; i++)
	{
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		if (!(phdrs[i].p_flags & PF_X))
			continue;

		if (text_address >= phdrs[i].p_vaddr &&
			text_address < phdrs[i].p_vaddr + phdrs[i].p_filesz)
		{
			segment_end = phdrs[i].p_vaddr +
				phdrs[i].p_filesz;

			printf("\nEspace apres .text dans le segment executable\n");
			printf("  Fin .text       : 0x%lx\n", text_end);
			printf("  Fin segment     : 0x%lx\n", segment_end);

			if (segment_end > text_end)
			{
				printf("  Espace restant  : 0x%lx (%lu octets)\n",
					segment_end - text_end,
					segment_end - text_end);
			}
			else
			{
				printf("  Espace restant  : 0 octet\n");
			}

			return;
		}
	}
}

int find_rodata(FILE *file, Elf64_Ehdr *header,
	Elf64_Addr *address, Elf64_Xword *size)
{
	Elf64_Shdr *sections;
	Elf64_Shdr string_section;
	char *strings;
	int i;

	sections = malloc(sizeof(Elf64_Shdr) * header->e_shnum);
	if (sections == NULL)
		return 0;

	if (fseek(file, header->e_shoff, SEEK_SET) != 0)
	{
		free(sections);
		return 0;
	}

	if (fread(sections, sizeof(Elf64_Shdr),
		header->e_shnum, file) != header->e_shnum)
	{
		free(sections);
		return 0;
	}

	string_section = sections[header->e_shstrndx];

	strings = malloc(string_section.sh_size);
	if (strings == NULL)
	{
		free(sections);
		return 0;
	}

	if (fseek(file, string_section.sh_offset, SEEK_SET) != 0)
	{
		free(strings);
		free(sections);
		return 0;
	}

	if (fread(strings, 1, string_section.sh_size, file)
		!= string_section.sh_size)
	{
		free(strings);
		free(sections);
		return 0;
	}

	for (i = 0; i < header->e_shnum; i++)
	{
		if (strcmp(strings + sections[i].sh_name, ".rodata") == 0)
		{
			*address = sections[i].sh_addr;
			*size = sections[i].sh_size;

			free(strings);
			free(sections);
			return 1;
		}
	}

	free(strings);
	free(sections);
	return 0;
}

int find_string(FILE *file, long offset, Elf64_Xword size,
	long *string_offset, long *string_size)
{
	unsigned char *data;
	long i;
	long start;

	data = malloc(size);
	if (data == NULL)
		return 0;

	if (fseek(file, offset, SEEK_SET) != 0)
	{
		free(data);
		return 0;
	}

	if (fread(data, 1, size, file) != size)
	{
		free(data);
		return 0;
	}

	start = -1;

	for (i = 0; i < (long)size; i++)
	{
		if (data[i] >= 32 && data[i] <= 126)
		{
			if (start < 0)
				start = i;
		}
		else if (data[i] == '\0' && start >= 0)
		{
			if (i - start >= 2)
			{
				*string_offset = offset + start;
				*string_size = i - start + 1;

				free(data);
				return 1;
			}

			start = -1;
		}
		else
		{
			start = -1;
		}
	}

	free(data);
	return 0;
}

int main(int argc, char **argv)
{
	FILE *file;
	Elf64_Ehdr header;
	Elf64_Phdr *phdrs;
	Elf64_Addr rodata_address;
	Elf64_Xword rodata_size;
	long rodata_offset;
	long string_offset;
	long string_size;

	if (argc != 3)
	{
		printf("Usage: %s <elf> <nouveau_texte>\n", argv[0]);
		return 1;
	}

	file = fopen(argv[1], "r+b");
	if (file == NULL)
	{
		perror("fopen");
		return 1;
	}

	if (!read_headers(file, &header, &phdrs))
	{
		printf("Erreur lecture ELF\n");
		fclose(file);
		return 1;
	}

	printf("ELF valide\n");
	printf("Entry point : 0x%lx\n", header.e_entry);

	print_executable_segment(phdrs, header.e_phnum);
	print_segment_gaps(phdrs, header.e_phnum);
	print_text_info(file, &header, phdrs, header.e_phnum);
	print_text_remaining_space(file, &header,
		phdrs, header.e_phnum);

	if (!find_rodata(file, &header,
		&rodata_address, &rodata_size))
	{
		printf("\nSection .rodata introuvable\n");
		free(phdrs);
		fclose(file);
		return 1;
	}

	rodata_offset = virtual_to_offset(
		phdrs,
		header.e_phnum,
		rodata_address
	);

	if (rodata_offset < 0)
	{
		printf("\nOffset .rodata introuvable\n");
		free(phdrs);
		fclose(file);
		return 1;
	}

	printf("\nSection .rodata\n");
	printf("  VA     : 0x%lx\n", rodata_address);
	printf("  Offset : 0x%lx\n", rodata_offset);
	printf("  Size   : 0x%lx\n", rodata_size);

	if (!find_string(file, rodata_offset, rodata_size,
		&string_offset, &string_size))
	{
		printf("\nAucune chaine trouvee\n");
		free(phdrs);
		fclose(file);
		return 1;
	}

	printf("\nChaine trouvee\n");
	printf("  Offset : 0x%lx\n", string_offset);
	printf("  Taille : %ld\n", string_size);

	if ((long)strlen(argv[2]) + 1 > string_size)
	{
		printf("\nNouveau texte trop long\n");
		free(phdrs);
		fclose(file);
		return 1;
	}

	if (fseek(file, string_offset, SEEK_SET) != 0)
	{
		printf("\nErreur de positionnement\n");
		free(phdrs);
		fclose(file);
		return 1;
	}

	if (fwrite(argv[2], 1, strlen(argv[2]) + 1, file)
		!= strlen(argv[2]) + 1)
	{
		printf("\nErreur d'ecriture\n");
		free(phdrs);
		fclose(file);
		return 1;
	}

	printf("\nModification effectuee.\n");

	free(phdrs);
	fclose(file);

	return 0;
}
