#include "parsElf.h"

int hex_to_dec(long h){

	char arr[16];
	sprintf(arr, "%lx", h);
	int i, num = 0, x = 1;

	for(i = strlen(arr) - 1; i >= 0; i--){

		if(arr[i] >= 48 && arr[i] <= 57){

			num = num + ((int)(arr[i] - 48) * x);
		
		} else if(arr[i] >= 97 && arr[i] <= 102){

			num = num + ((int)(arr[i] - 87) * x);
		}

	x = x * 16;

	}

	return num;

}

char *hex_to_bin(long h, char **bin){

	int dec = hex_to_dec(h);
	
	while(dec){

		if(dec%2){

			strcat(*bin, "1");

		} else {

			strcat(*bin, "0");

		}

		dec = dec / 2;

	}

	return *bin;
}

void init(uint8_t **mem, char *c, Elf64_Ehdr **ehdr){

	struct stat st;
	int fd;

	fd = open(c, O_RDONLY);

	if (!fd) {

		perror("ppen function error");
		exit(1);

	}

	if(fstat(fd, &st)){

		perror("fstat function error");
		exit(1);

	}

	*mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

	if(mem == MAP_FAILED){

		perror("mmap function error");
		exit(1);

	}

	if((*mem)[0] != 0x7f && strcmp(&((*mem)[1]), "ELF")){

		printf("Not an ELF file\n");
		exit(0);

	}

	if((*mem)[4] != ELFCLASS64){

		printf("Not a 64 bit ELF file\n");
		exit(0);
	}

	*ehdr = (Elf64_Ehdr *)*mem;

}

void print_ehdr(Elf64_Ehdr *ehdr){

	printf("ELF header :\n\tMagic number :\t\t\t\tx%d%c%c%c\n", ehdr->e_ident[EI_MAG0], ehdr->e_ident[EI_MAG1],
	ehdr->e_ident[EI_MAG2], ehdr->e_ident[EI_MAG3]);
	printf("\tClass :\t\t\t\t\tELF64\n");

	switch(ehdr->e_ident[EI_DATA]){

		case ELFDATA2LSB :

			printf("\tEncoding :\t\t\t\tLittle-endian\n");
			break;

		case ELFDATA2MSB :

			printf("\tEncoding :\t\t\t\tBig-endian\n");
			break;

		default :

			printf("\tEncoding :\t\t\t\tUnknown\n");
			break;
	}

	switch(ehdr->e_ident[EI_VERSION]){

		case EV_NONE :

			printf("\tVersion :\t\t\t\tInvalid\n");
			break;

		case EV_CURRENT :

			printf("\tVersion :\t\t\t\tCurrent\n");
			break;

		default :

			printf("\tVersion :\t\t\t\tUnknown\n");
			break;
	}

	switch(ehdr->e_ident[EI_OSABI]){

		case ELFOSABI_NONE : 

			printf("\tOS/ABI :\t\t\t\tUNIX System V ABI\n");
			break;

		case ELFOSABI_HPUX :

			printf("\tOS/ABI :\t\t\t\tHP-UX ABI\n");
			break;

		case ELFOSABI_NETBSD :

			printf("\tOS/ABI :\t\t\t\tNetBSD ABI\n");
			break;

		case ELFOSABI_LINUX :

			printf("\tOS/ABI :\t\t\t\tLinux ABI\n");
			break;

		case ELFOSABI_SOLARIS :

			printf("\tOS/ABI :\t\t\t\tSolaris ABI\n");
			break;

		case ELFOSABI_IRIX :

			printf("\tOS/ABI :\t\t\t\tIRIX ABI\n");
			break;

		case ELFOSABI_FREEBSD : 

			printf("\tOS/ABI :\t\t\t\tFreeBSD ABI\n");
			break;

		case ELFOSABI_TRU64 :

			printf("\tOS/ABI :\t\t\t\tTRU64 UNIX ABI\n");
			break;

		case ELFOSABI_ARM :

			printf("\tOS/ABI :\t\t\t\tARM architecture ABI\n");
			break;
		
		case ELFOSABI_STANDALONE :

			printf("\tOS/ABI :\t\t\t\tStand-alone (embedded)\n");
			break;

		default :

			printf("\tOS/ABI :\t\t\t\tUnknown\n");
			break;

	}

	printf("\tABI Version :\t\t\t\t%d\n", ehdr->e_ident[EI_ABIVERSION]);

	switch(ehdr->e_type){

		case ET_NONE :

			printf("\tFile type :\t\t\t\tUnknown\n");
			break;

		case ET_REL :

			printf("\tFile type :\t\t\t\tRelocatable\n");
			break;

		case ET_EXEC :

			printf("\tFile type :\t\t\t\tExecutable\n");
			break;

		case ET_DYN :

			printf("\tFile type :\t\t\t\tShared object\n");
			break;

		case ET_CORE :

			printf("\tFile type :\t\t\t\tCore file\n");
			break;

		default :

			printf("\tFile type :\t\t\t\tUnknown\n");
			break;

	}

	printf("\tEntry point :\t\t\t\t0x%lx\n", ehdr->e_entry);

	switch(ehdr->e_phoff){

		case 0 :

			printf("\tProgram header table :\t\t\tNone\n");
			break;
		
		default :

			printf("\tProgram header table :\t\t\t%d bytes\n", hex_to_dec(ehdr->e_phoff));
			break;

	}

	switch(ehdr->e_shoff){

		case 0 :

			printf("\tProgram section table :\t\t\tNone\n");
			break;

		default :

			printf("\tProgram section table :\t\t\t%d bytes\n", hex_to_dec(ehdr->e_shoff));
			break;

	}

	printf("\tFlags:\t\t\t\t\t0x0\n");
	printf("\tElf header size :\t\t\t%d bytes\n", hex_to_dec(ehdr->e_ehsize));
	printf("\tProgram header size :\t\t\t%d bytes\n", hex_to_dec(ehdr->e_phentsize));
	printf("\tNumber of program headers :\t\t%d\n", hex_to_dec(ehdr->e_phnum));
	printf("\tSection header size :\t\t\t%d bytes\n", hex_to_dec(ehdr->e_shentsize));
	printf("\tNumber of section headers :\t\t%d\n", hex_to_dec(ehdr->e_shnum));

	if(ehdr->e_shstrndx == SHN_UNDEF){

		printf("\tSection header string table index :\t\tNone\n");

	} else {

		printf("\tSection header string table index :\t%d\n", hex_to_dec(ehdr->e_shstrndx));

	}	

}

void print_phdr(Elf64_Ehdr *ehdr, uint8_t *mem){

	int offset = hex_to_dec(ehdr->e_phoff);
	int phnum = hex_to_dec(ehdr->e_phnum);
	int phdr_size = hex_to_dec(ehdr->e_phentsize);
	int i;
	Elf64_Phdr *phdr = (Elf64_Phdr *)&(mem[offset]);
	char *flags;
	printf("There are %d program headers starting at offset %d\n\n", phnum, offset);
	printf(" Type\t\tOffset\t\t VirtAddr\tPhysAddr\n\t\tFileSize\t MemSize\tFlags   Align\n\n");

	for(i = 0; i < phnum; i++){

		switch(phdr->p_type){

			case PT_LOAD :

				printf(" LOAD\t\t");
				break;

			case PT_DYNAMIC :

				printf(" DYN\t\t");
				break;

			case PT_INTERP :

				printf(" INTERP\t\t");
				break;

			case PT_PHDR :

				printf(" PHDR\t\t");
				break;

			case PT_NOTE :

				printf(" NOTE\t\t");
				break;

			default :

				printf(" UNKNOWN\t");
				break;

		}

		printf("0x%-15lx", phdr->p_offset);
		printf("0x%-13lx", phdr->p_vaddr);
		printf("0x%lx\n\t\t", phdr->p_paddr);
		printf("0x%-15lx", phdr->p_filesz);
		printf("0x%-13lx", phdr->p_memsz);

		flags = (char *)malloc(sizeof(char) * 10);
		hex_to_bin(phdr->p_flags, &flags);

		if(flags[2] == 49){

			printf("R");

		}

		if(flags[1] == 49){

			printf("W");

		}

		if(flags[0] == 49){

			printf("X");

		}

		free(flags);

		printf("\t0x%lx\n", phdr->p_align);

		offset = offset + phdr_size;
		phdr = (Elf64_Phdr *)&(mem[offset]);
		
	}

}

void print_shdr(Elf64_Ehdr *ehdr, uint8_t *mem){

	int offset = hex_to_dec(ehdr->e_shoff);
	int shnum = hex_to_dec(ehdr->e_shnum);
	int shdr_size = hex_to_dec(ehdr->e_shentsize);
	int i;
	Elf64_Shdr *shdr = (Elf64_Shdr *)&(mem[offset]);
	Elf64_Shdr *shdr_strtb = (Elf64_Shdr *)&(mem[offset + (ehdr->e_shstrndx * shdr_size)]);
	uint8_t *sh_strtb_addr = &mem[shdr_strtb->sh_offset];
	char *flags;
	int set_flag = 0;

	printf("There are %d section headers starting at offset %d\n", shnum, offset);
	printf("Supported flags : A (alloc), W (write), X (exec)\n\n");
	printf("  [Nr] Name\t\t    Type\t   Address\t      Offset\n       Size\t\t    EntSize\t   Flags  Link  Info  Align\n\n");

	for(i = 0; i < shnum; i++){

		if(ehdr->e_shstrndx == SHN_UNDEF){

			printf("  [%2d] Unknown\t\t\t", i);

		} else {

			printf("  [%2d] %-21s", i, &sh_strtb_addr[shdr->sh_name]);

		}

		switch(shdr->sh_type){

			case SHT_NULL :

				printf("NULL\t   ");
				break;

			case SHT_PROGBITS :

				printf("PROGIBITS      ");
				break;

			case SHT_SYMTAB :

				printf("SYMTAB\t   ");
				break;

			case SHT_STRTAB :

				printf("STRTAB\t   ");
				break;

			case SHT_RELA :

				printf("RELA\t   ");
				break;

			case SHT_HASH :

				printf("HASH\t   ");
				break;

			case SHT_DYNAMIC :

				printf("DYNAMIC\t   ");
				break;

			case SHT_NOTE :

				printf("NOTE\t   ");
				break;

			case SHT_NOBITS :

				printf("NOBITS\t   ");
				break;

			case SHT_REL :

				printf("REL\t   ");
				break;

			case SHT_DYNSYM :

				printf("DYNSYM\t   ");
				break;

			default :

				printf("UNKNOWN\t   ");
				break;

		}

		printf("0x%-12lx", shdr->sh_addr);
		printf("     0x%lx\n", shdr->sh_offset);
		printf("       0x%-19lx", shdr->sh_size);
		printf("0x%-12lx ", shdr->sh_entsize);
		
		flags = (char *)malloc(sizeof(char) * 10);
		hex_to_bin(shdr->sh_flags, &flags);

		if(flags[0] == 49){

			set_flag = 1;
			printf("W");

		}

		if(flags[1] == 49){

			set_flag = 1;
			printf("A");

		}

		if(flags[2] == 49){

			set_flag = 1;
			printf("X");

		}

		if(!set_flag){

			printf(" ");
			set_flag = 0;

		}

		free(flags);

		printf("%7x ", shdr->sh_link);
		printf("%5x ", shdr->sh_info);
		printf("%5lx\n\n", shdr->sh_addralign);

		offset = offset + shdr_size;
		shdr = (Elf64_Shdr *)&(mem[offset]);

	}

}

void print_symts(Elf64_Ehdr *ehdr, uint8_t *mem){

	int shdr_offset = hex_to_dec(ehdr->e_shoff);
	int offset = shdr_offset;
	int shnum = hex_to_dec(ehdr->e_shnum);
	int shdr_size = hex_to_dec(ehdr->e_shentsize);
	int i;
	Elf64_Shdr *shdr = (Elf64_Shdr *)&(mem[shdr_offset]);	

	Elf64_Shdr *dynsym_shdr = NULL;
	Elf64_Shdr *dyntab_shdr;
	Elf64_Shdr *symtab_shdr = NULL;
	Elf64_Shdr *strtab_shdr;

	Elf64_Sym *dynsym_addr;
	char *dyntab_addr;
	Elf64_Sym *symtab_addr;
	char *strtab_addr;

	int dynsym_offset;
	int sym_offset;

	for(i = 0; i < shnum; i++){

		if(shdr->sh_type == SHT_DYNSYM){

			dynsym_shdr = shdr;

		}

		
		if(shdr->sh_type == SHT_SYMTAB){

			symtab_shdr = shdr;

		}

		offset = offset + shdr_size;
		shdr = (Elf64_Shdr *)&mem[offset];

	}

	if(dynsym_shdr != NULL){

		dynsym_addr = (Elf64_Sym *)&mem[dynsym_shdr->sh_offset];
		dynsym_offset = dynsym_shdr->sh_offset;
		dyntab_shdr = (Elf64_Shdr *)&mem[shdr_offset + dynsym_shdr->sh_link * hex_to_dec(sizeof(Elf64_Shdr))];
		dyntab_addr = (char *)&mem[dyntab_shdr->sh_offset];

		offset = shdr_offset;
		shdr = (Elf64_Shdr *)&(mem[shdr_offset]);	
		
		printf("Symbol table '.dynsym' contains %ld entries :\n", dynsym_shdr->sh_size / dynsym_shdr->sh_entsize);
		printf("   Num:   Value   Size Type\tBind   Vis      Ndx Name\n");

		for(i = 0; i < (dynsym_shdr->sh_size / dynsym_shdr->sh_entsize); i++){

			printf("%6d: ", i);
			printf("%7lx", dynsym_addr->st_value);
			printf("%7ld", dynsym_addr->st_size);

			switch(ELF64_ST_TYPE(dynsym_addr->st_info)){

				case STT_NOTYPE :

					printf(" NOTYPE   ");
					break;

				case STT_OBJECT :

					printf(" OBJECT ");
					break;

				case STT_FUNC :

					printf(" FUNCTION ");
					break;

				case STT_SECTION :

					printf(" SECTION ");
					break;

				case STT_FILE :

					printf(" FILE  ");
					break;

				default :

					printf(" UNKNOWN ");
					break;

			}

			switch(ELF64_ST_BIND(dynsym_addr->st_info)){

				case STB_LOCAL :

					printf("LOCAL  ");
					break;

				case STB_GLOBAL :

					printf("GLOBAL ");
					break;

				case STB_WEAK :
	 
					printf("WEAK   ");
					break; 

				default :

					printf("UNKNOWN ");
					break;
					
			}

			switch(dynsym_addr->st_other){

				case STV_DEFAULT :

					printf("DEFAULT");
					break;

				case STV_INTERNAL:

					printf("INTERNAL");
					break;

				case STV_HIDDEN:

					printf("HIDDEN");
					break;

				case STV_PROTECTED:

					printf("PROTECTED");
					break;

				default :

					printf("UNKNOWN");
					break;
					
			}

			if(!dynsym_addr->st_shndx){

				printf("  UND ");

			} else {

				printf("%5d ", dynsym_addr->st_shndx);
			}

			printf("%s\n", (char *)&dyntab_addr[dynsym_addr->st_name]);

			dynsym_offset = dynsym_offset + 24;
			dynsym_addr = (Elf64_Sym *)&mem[dynsym_offset];
			
		}

		offset = shdr_offset;
		shdr = (Elf64_Shdr *)&(mem[shdr_offset]);	

	} else {

		printf("	NO DYNAMIC SYMBOL TABLE\n");

	}

	if(symtab_shdr != NULL){

		symtab_addr = (Elf64_Sym *)&mem[symtab_shdr->sh_offset];
		sym_offset = symtab_shdr->sh_offset;
		strtab_shdr = (Elf64_Shdr *)&mem[shdr_offset + symtab_shdr->sh_link * hex_to_dec(sizeof(Elf64_Shdr))];
		strtab_addr = (char *)&mem[strtab_shdr->sh_offset];

		printf("\n\nSymbol table '.symtab' contains %ld entries :\n", symtab_shdr->sh_size / symtab_shdr->sh_entsize);
		printf("   Num:   Value   Size Type\tBind   Vis       Ndx Name\n");

		for(i = 0; i < (symtab_shdr->sh_size / symtab_shdr->sh_entsize); i++){

			printf("%6d: ", i);
			printf("%7lx", symtab_addr->st_value);
			printf("%7ld", symtab_addr->st_size);

			switch(ELF64_ST_TYPE(symtab_addr->st_info)){

				case STT_NOTYPE :

					printf(" NOTYPE   ");
					break;

				case STT_OBJECT :

					printf(" OBJECT   ");
					break;

				case STT_FUNC :

					printf(" FUNCTION ");
					break;

				case STT_SECTION :

					printf(" SECTION  ");
					break;

				case STT_FILE :

					printf(" FILE     ");
					break;

				default :

					printf(" UNKNOWN ");
					break;

			}

			switch(ELF64_ST_BIND(symtab_addr->st_info)){

				case STB_LOCAL :

					printf("LOCAL  ");
					break;

				case STB_GLOBAL :

					printf("GLOBAL ");
					break;

				case STB_WEAK :
	 
					printf("WEAK   ");
					break; 

				default :

					printf("UNKNOWN ");
					break;
					
			}

			switch(symtab_addr->st_other){

				case STV_DEFAULT :

					printf("DEFAULT");
					break;

				case STV_INTERNAL:

					printf("INTERNAL");
					break;

				case STV_HIDDEN:

					printf("HIDDEN ");
					break;

				case STV_PROTECTED:

					printf("PROTECTED");
					break;

				default :

					printf("UNKNOWN");
					break;
					
			}

			if(!symtab_addr->st_shndx){

				printf("   UND ");

			} else if(symtab_addr->st_shndx == 65521){

				printf("   ABS ");

			} else {

				printf("%6d ", symtab_addr->st_shndx);
			}

			printf("%s\n", (char *)&strtab_addr[symtab_addr->st_name]);

			sym_offset = sym_offset + 24;
			symtab_addr = (Elf64_Sym *)&mem[sym_offset];
			
		}

	} else {

		printf("\n	NO SYMBOL TABLE\n");

	}

}
