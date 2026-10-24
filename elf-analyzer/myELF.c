#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <stdbool.h>
#define MAX_FILES 2

char debug_mode = 0; // Flag to toggle debug messages
int fds[MAX_FILES] = {-1, -1}; //// Array to store the file descriptors of the opened ELF files
void *map_starts[MAX_FILES] = {NULL, NULL}; // Array of pointers to the memory-mapped starting addresses of the files
size_t file_sizes[MAX_FILES] = {0, 0}; // Array to store the exact sizes of the mapped files
int num_open_files = 0; // Counter tracking the current number of successfully open and mapped files
char file_names[MAX_FILES][256]; // Array to store the names of the opened files

struct menu_option {
    char *name;
    char index;
    void (*fun)(); 
};
// Toggles debug mode on/off and prints status to stderr 
void toggleDebugMode() {
    if (debug_mode) {
        debug_mode = 0;
        fprintf(stderr,"Debug flag now off\n");
    } 
    else {
        debug_mode = 1;
        fprintf(stderr,"Debug flag now on\n");
    }
}

// Opens, memory-maps, and validates an ELF file, printing its core header information.
void examineELFFile() {
    if (num_open_files >= MAX_FILES) {
        printf("Error: Maximum number of open files (%d) reached.\n", MAX_FILES);
        return;
    }
    char filename[256];
    printf("Enter ELF file name: ");
    if (fgets(filename, sizeof(filename), stdin) == NULL) 
        return;
    filename[strcspn(filename, "\n")] = 0; 
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Error opening file");
        return;
    }
    struct stat fd_stat;
    if (fstat(fd, &fd_stat) != 0) {
        perror("Error stating file");
        close(fd);
        return;
    }
    void *map_start = mmap(NULL, fd_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        perror("Error mapping file");
        close(fd);
        return;
    }
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||ehdr->e_ident[EI_MAG1] != ELFMAG1 ||ehdr->e_ident[EI_MAG2] != ELFMAG2 ||ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        printf("Error: File is not a valid ELF file.\n");
        munmap(map_start, fd_stat.st_size);
        close(fd);
        return;
    }

    printf("\nELF Header Information:\n");
    printf("  Magic bytes 1,2,3:              %c %c %c\n", 
           ehdr->e_ident[EI_MAG1], ehdr->e_ident[EI_MAG2], ehdr->e_ident[EI_MAG3]);
    
    printf("  Data encoding:                  ");
    switch (ehdr->e_ident[EI_DATA]) {
        case ELFDATA2LSB: printf("2's complement, little endian\n"); break;
        case ELFDATA2MSB: printf("2's complement, big endian\n"); break;
        default: printf("Unknown data format\n"); break;
    }

    printf("  Entry point:                    0x%x\n", ehdr->e_entry);
    printf("  Section header table offset:    %d (bytes into file)\n", ehdr->e_shoff);
    printf("  Number of section headers:      %d\n", ehdr->e_shnum);
    printf("  Size of section header entry:   %d (bytes)\n", ehdr->e_shentsize);
    printf("  Program header table offset:    %d (bytes into file)\n", ehdr->e_phoff);
    printf("  Number of program headers:      %d\n", ehdr->e_phnum);
    printf("  Size of program header entry:   %d (bytes)\n", ehdr->e_phentsize);
    fds[num_open_files] = fd;
    map_starts[num_open_files] = map_start;
    file_sizes[num_open_files] = fd_stat.st_size;
    strcpy(file_names[num_open_files], filename);
    num_open_files++;
    printf("\nFile mapped successfully. Total open files: %d\n", num_open_files);
}

// Iterates through all mapped ELF files and prints the details and names of their sections.
void printSectionNames() { 
    if (num_open_files == 0) {
        printf("Error: No ELF files are currently mapped.\n");
        return;
    }
    for (int i = 0; i < num_open_files; i++) {
        void *map_start = map_starts[i];
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;
        Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)map_start + ehdr->e_shoff);
        Elf32_Shdr *sh_strtab_hdr = &shdr[ehdr->e_shstrndx];
        char *sh_strtab = (char *)map_start + sh_strtab_hdr->sh_offset;
        if (debug_mode) {
            fprintf(stderr, "[Debug] File %s: shstrndx = %d\n", file_names[i], ehdr->e_shstrndx);
            fprintf(stderr, "[Debug] File %s: shstrtab offset = 0x%x\n", file_names[i], sh_strtab_hdr->sh_offset);
        }
        printf("File %s sections:\n", file_names[i]);
        printf("[index] section_name       section_address section_offset section_size section_type\n");
        for (int j = 0; j < ehdr->e_shnum; j++) {
            char *section_name = sh_strtab + shdr[j].sh_name;
            if (debug_mode) 
                fprintf(stderr, "[Debug] Section [%d] name offset: %d\n", j, shdr[j].sh_name);
            printf("[%2d]    %-18s %08x      %08x       %08x     %d\n",
                   j,
                   section_name,
                   shdr[j].sh_addr,
                   shdr[j].sh_offset,
                   shdr[j].sh_size,
                   shdr[j].sh_type);
        }
        printf("\n");
    }
 }

// Locates and prints the symbol table details (value, section, and name) for all mapped ELF files.
void printSymbols() { 
    if (num_open_files == 0) {
        printf("Error: No ELF files are currently mapped.\n");
        return;
    }
    for (int i = 0; i < num_open_files; i++) {
        void *map_start = map_starts[i];
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;
        Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)map_start + ehdr->e_shoff);
        char *sh_strtab = (char *)map_start + shdr[ehdr->e_shstrndx].sh_offset;
        Elf32_Shdr *symtab_hdr = NULL;
        Elf32_Shdr *strtab_hdr = NULL;
        for (int j = 0; j < ehdr->e_shnum; j++) {
            if (shdr[j].sh_type == SHT_SYMTAB) {
                symtab_hdr = &shdr[j];
                strtab_hdr = &shdr[symtab_hdr->sh_link];
                break;
            }
        }
        if (symtab_hdr == NULL) {
            printf("Error: No symbol table found in File %d.\n", i + 1);
            continue;
        }
        int num_symbols = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
        Elf32_Sym *symtab = (Elf32_Sym *)((char *)map_start + symtab_hdr->sh_offset);
        char *strtab = (char *)map_start + strtab_hdr->sh_offset;
        if (debug_mode) {
            fprintf(stderr, "[Debug] File %d Symbol Table:\n", i + 1);
            fprintf(stderr, "  - Size: %d bytes\n", symtab_hdr->sh_size);
            fprintf(stderr, "  - Number of symbols: %d\n", num_symbols);
        }
        printf("File %d symbols:\n", i + 1);
        printf("[index] value     section_index section_name     symbol_name\n");
        for (int j = 0; j < num_symbols; j++) {
            Elf32_Sym *sym = &symtab[j];
            char *sec_name;
            char sec_index_str[15];
            if (sym->st_shndx == SHN_UNDEF) {
                sec_name = "UNDEF";
                strcpy(sec_index_str, "UND");
            } 
            else if (sym->st_shndx == SHN_ABS) {
                sec_name = "ABS";
                strcpy(sec_index_str, "ABS");
            } 
            else if (sym->st_shndx == SHN_COMMON) {
                sec_name = "COMMON";
                strcpy(sec_index_str, "COM");
            } 
            else {
                sec_name = sh_strtab + shdr[sym->st_shndx].sh_name;
                sprintf(sec_index_str, "%d", sym->st_shndx);
            }
            char *sym_name = strtab + sym->st_name;
            printf("[%2d]    %08x  %-13s %-16s %s\n",
                   j,
                   sym->st_value,
                   sec_index_str,
                   sec_name,
                   sym_name);
        }
        printf("\n");
    }
} 

// Displays the relocation table entries for all mapped ELF files.
void printRelocations() {
    if (num_open_files == 0) {
        printf("Error: No ELF files are currently mapped.\n");
        return;
    }
    for (int i = 0; i < num_open_files; i++) {
        void *map_start = map_starts[i];
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;
        Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)map_start + ehdr->e_shoff);
        printf("File %d relocations:\n", i + 1);
        printf("[index] location  symbol_name      type\n");
        int found = 0;
        for (int j = 0; j < ehdr->e_shnum; j++) {
            if (shdr[j].sh_type == SHT_REL) {
                found = 1;
                Elf32_Rel *rel = (Elf32_Rel *)((char *)map_start + shdr[j].sh_offset);
                int num_rel = shdr[j].sh_size / shdr[j].sh_entsize;
                Elf32_Sym *symtab = (Elf32_Sym *)((char *)map_start + shdr[shdr[j].sh_link].sh_offset);
                char *strtab = (char *)map_start + shdr[shdr[shdr[j].sh_link].sh_link].sh_offset;
                for (int k = 0; k < num_rel; k++) {
                    int sym_idx = ELF32_R_SYM(rel[k].r_info);
                    int type = ELF32_R_TYPE(rel[k].r_info);
                    char *sym_name = (sym_idx != 0) ? (strtab + symtab[sym_idx].st_name) : "";

                    printf("[%2d]    %08x  %-16s %d\n", k, rel[k].r_offset, sym_name, type);
                }
            }
        }
        if (!found) {
            printf("No relocations\n");
        }
        printf("\n");
    }
 }

 // Checks two mapped ELF files for symbol merge conflicts, reporting undefined and multiply-defined symbols.
void checkFilesForMerge() {
    if (num_open_files != 2) {
        printf("Error: Exactly 2 ELF files must be opened for merge check.\n");
        return;
    }
    Elf32_Sym *symtabs[2] = {NULL, NULL};
    char *strtabs[2] = {NULL, NULL};
    int num_symbols[2] = {0, 0};
    for (int i = 0; i < 2; i++) {
        void *map_start = map_starts[i];
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;
        Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)map_start + ehdr->e_shoff);
        int symtab_count = 0;
        for (int j = 0; j < ehdr->e_shnum; j++) {
            if (shdr[j].sh_type == SHT_SYMTAB) {
                symtab_count++;
                symtabs[i] = (Elf32_Sym *)((char *)map_start + shdr[j].sh_offset);
                strtabs[i] = (char *)map_start + shdr[shdr[j].sh_link].sh_offset;
                num_symbols[i] = shdr[j].sh_size / shdr[j].sh_entsize;
            }
        }
        if (symtab_count != 1) {
            printf("feature not supported\n");
            return;
        }
    }
    for (int i = 1; i < num_symbols[0]; i++) {
        Elf32_Sym *sym1 = &symtabs[0][i];
        char *name1 = strtabs[0] + sym1->st_name;
        if (strlen(name1) == 0) 
            continue;
        Elf32_Sym *sym2 = NULL;
        for (int j = 1; j < num_symbols[1]; j++) {
            char *name2 = strtabs[1] + symtabs[1][j].st_name;
            if (strcmp(name1, name2) == 0) {
                sym2 = &symtabs[1][j];
                break; 
            }
        }
        int defined1 = (sym1->st_shndx != SHN_UNDEF);
        int defined2 = (sym2 != NULL && sym2->st_shndx != SHN_UNDEF);
        if (!defined1) {
            if (sym2 == NULL || !defined2) {
                printf("Symbol %s undefined\n", name1);
            }
        } 
        else {
            if (sym2 != NULL && defined2) 
                printf("Symbol %s multiply defined\n", name1);
        }
    }
    for (int i = 1; i < num_symbols[1]; i++) {
        Elf32_Sym *sym2 = &symtabs[1][i];
        char *name2 = strtabs[1] + sym2->st_name;
        if (strlen(name2) == 0) 
            continue;
        if (sym2->st_shndx == SHN_UNDEF) {
            int found_in_1 = 0;
            for (int j = 1; j < num_symbols[0]; j++) {
                char *name1 = strtabs[0] + symtabs[0][j].st_name;
                if (strcmp(name2, name1) == 0) {
                    found_in_1 = 1;
                    break;
                }
            }
            if (!found_in_1) 
                printf("Symbol %s undefined\n", name2);
        }
    }
}

void mergeELFFiles() {
    // 1. Verify that exactly 2 ELF files are open
    if (num_open_files != 2) {
        printf("Error: Exactly 2 ELF files must be opened for merging.\n");
        return;
    }

    void *map1 = map_starts[0];
    void *map2 = map_starts[1];
    Elf32_Ehdr *ehdr1 = (Elf32_Ehdr *)map1;
    Elf32_Ehdr *ehdr2 = (Elf32_Ehdr *)map2;
    
    // Pointers to the Section Header tables
    Elf32_Shdr *shdr1 = (Elf32_Shdr *)((char *)map1 + ehdr1->e_shoff);
    Elf32_Shdr *shdr2 = (Elf32_Shdr *)((char *)map2 + ehdr2->e_shoff);
    
    // Pointers to the String Tables to search for sections by name
    char *shstrtab1 = (char *)map1 + shdr1[ehdr1->e_shstrndx].sh_offset;
    char *shstrtab2 = (char *)map2 + shdr2[ehdr2->e_shstrndx].sh_offset;

    // 2. Open the destination file out.ro
    int fd_out = open("out.ro", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out < 0) {
        perror("Error creating out.ro");
        return;
    }

    // 3. Write the initial ELF Header (copied directly from file 1)
    Elf32_Ehdr out_ehdr;
    memcpy(&out_ehdr, ehdr1, sizeof(Elf32_Ehdr));
    write(fd_out, &out_ehdr, sizeof(Elf32_Ehdr));
    int current_offset = sizeof(Elf32_Ehdr);

    // 4. Create a new Section Header table in memory (to be updated iteratively)
    Elf32_Shdr out_shdr[ehdr1->e_shnum];
    memcpy(out_shdr, shdr1, ehdr1->e_shnum * sizeof(Elf32_Shdr));

    // 5. Iterate over all sections and merge them into the new file
    for (int i = 1; i < ehdr1->e_shnum; i++) {
        char *name1 = shstrtab1 + shdr1[i].sh_name;

        // Handle sections that do not occupy physical space in the file (e.g., .bss)
        if (shdr1[i].sh_type == SHT_NOBITS) {
            out_shdr[i].sh_offset = current_offset;
            // If it's .bss, accumulate the sizes but do not write anything to the file
            if (strcmp(name1, ".bss") == 0) {
                for (int j = 1; j < ehdr2->e_shnum; j++) {
                    char *name2 = shstrtab2 + shdr2[j].sh_name;
                    if (strcmp(name1, name2) == 0) {
                        out_shdr[i].sh_size += shdr2[j].sh_size;
                        break;
                    }
                }
            }
            continue;
        }

        // Sections that require concatenation (.text, .data, .rodata)
        if (strcmp(name1, ".text") == 0 || strcmp(name1, ".data") == 0 || strcmp(name1, ".rodata") == 0) {
            
            // Find the corresponding section in file 2
            Elf32_Shdr *match_shdr2 = NULL;
            for (int j = 1; j < ehdr2->e_shnum; j++) {
                char *name2 = shstrtab2 + shdr2[j].sh_name;
                if (strcmp(name1, name2) == 0) {
                    match_shdr2 = &shdr2[j];
                    break;
                }
            }

            out_shdr[i].sh_offset = current_offset;
            
            // a) Write the content from the first file
            write(fd_out, (char *)map1 + shdr1[i].sh_offset, shdr1[i].sh_size);
            current_offset += shdr1[i].sh_size;
            
            // b) Write the content from the second file (if a match was found)
            if (match_shdr2 != NULL) {
                write(fd_out, (char *)map2 + match_shdr2->sh_offset, match_shdr2->sh_size);
                current_offset += match_shdr2->sh_size;
                out_shdr[i].sh_size = shdr1[i].sh_size + match_shdr2->sh_size;
            }
        } 
        else {
            // Other sections (symbol table, string table, etc.) - copy directly from file 1
            out_shdr[i].sh_offset = current_offset;
            write(fd_out, (char *)map1 + shdr1[i].sh_offset, shdr1[i].sh_size);
            current_offset += shdr1[i].sh_size;
        }
    }

    // 6. Write the updated Section Header table to the end of the file
    out_ehdr.e_shoff = current_offset; // Save the new offset of the table
    write(fd_out, out_shdr, ehdr1->e_shnum * sizeof(Elf32_Shdr));

    // 7. Update the ELF Header at the beginning of the file to point to the new table
    lseek(fd_out, 0, SEEK_SET);
    write(fd_out, &out_ehdr, sizeof(Elf32_Ehdr));

    // Finalize and close
    close(fd_out);
    printf("Merge completed successfully. Output saved to 'out.ro'.\n");
}


// Prints exit message and terminates the program 
void quit() {
    for (int i = 0; i < num_open_files; i++) {
        if (map_starts[i] != NULL) {
            munmap(map_starts[i], file_sizes[i]);
        }
        if (fds[i] != -1) {
            close(fds[i]);
        }
    }
    if (debug_mode) {
        printf("Cleaned up resources. Exiting...\n");
    }
    exit(0);
}

int main() {
    struct menu_option menu[] = {
        {"Toggle Debug Mode",'D', toggleDebugMode},
        {"Examine ELF File",'F', examineELFFile},
        {"Print Section Names",'N', printSectionNames},
        {"Print Symbols",'S', printSymbols},
        {"Print Relocations",'R', printRelocations},
        {"Check Files for Merge",'C', checkFilesForMerge},
        {"Merge ELF Files",'M', mergeELFFiles},
        {"Quit",'Q', quit},
        {NULL, 0, NULL} 
    };
    char choice_index; //Stores the specific character the user chose from the menu
    bool found; //A flag used to indicate if the user's input matches a valid menu option
    bool flag_EOF = false;
    while (1) {
        found = false;
        printf("Choose action:\n");
        for (int i = 0; menu[i].name != NULL; i++) {
            printf("%c) %s\n", menu[i].index, menu[i].name);
        }
        printf("Option: ");
        char input[10];
        do {
          if(fgets(input, sizeof(input), stdin) == NULL) {
            flag_EOF = true;
            break;
          }
          choice_index = input[0]; 
        } while(input[0] == '\n');
        if(flag_EOF)
          break;
        for(int i=0; menu[i].name!=NULL && !found; i++) {   
            if(choice_index == menu[i].index) {
                found = true; 
                menu[i].fun();
            }
        }
        if(!found)
            printf("Invalid choice\n");
    }
    return 0;
}