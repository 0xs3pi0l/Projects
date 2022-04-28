#include "parsElf.h"

int main(int argc, char **argv){
	
	uint8_t *mem;
	Elf64_Ehdr *ehdr;

	if(argc == 1){

		printf("Usage : elfReader [flag] <file>\nUse 'elfReader -h' for help\n");
		exit(0);

	}

	if(argc == 2 && !strcmp(argv[1], "-h")){

		printf("Usage : elfReader [flag] <file>\nFlags :\n\t-h\t\tGet help\n\t-h <file>\tPrint file header\n\t-p <file>\tPrint program header table\n\t-s <file>\tPrint section header table\n\t-S <file>\tPrint symbol tables\n");
		exit(0);

	} else if(argc == 2 && strcmp(argv[1], "-h")){

		printf("Wrong syntax. Use 'elfReader -h' for help\n");
		exit(0);

	}

	init(&mem, argv[2], &ehdr);

	if(argc == 3){

		if(!strcmp(argv[1], "-h")){

			print_ehdr(ehdr);

		} else if (!strcmp(argv[1], "-p")){

			print_phdr(ehdr, mem);

		} else if (!strcmp(argv[1], "-S")){

			print_shdr(ehdr, mem);

		} else if (!strcmp(argv[1], "-s")){

			print_symts(ehdr, mem);

		} else if (!strcmp(argv[1], "-a")){

			printf("\nELF FILE HEADER\n\n");
			print_ehdr(ehdr);
			printf("\n");
			printf("PROGRAM HEADER TABLE\n\n");
			print_phdr(ehdr, mem);
			printf("\n");
			printf("SECTION HEADER TABLE\n\n");
			print_shdr(ehdr, mem);
			printf("\n");
			printf("SYMBOL TABLES\n\n");
			print_symts(ehdr, mem);

		}
		
	} else {

		printf("Wrong syntax. Use 'elfReader -h' for help\n");
		exit(0);

	}

	return 0;

}



