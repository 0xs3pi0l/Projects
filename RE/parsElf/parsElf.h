#include <stdio.h>
#include <elf.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>


int hex_to_dec(long);
char *hex_to_bin(long , char **);
void init(uint8_t **, char *, Elf64_Ehdr **);
void print_ehdr(Elf64_Ehdr *);
void print_phdr(Elf64_Ehdr *, uint8_t *);
void print_shdr(Elf64_Ehdr *, uint8_t *);
void print_symts(Elf64_Ehdr *, uint8_t *);