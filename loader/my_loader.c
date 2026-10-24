#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

extern int startup(int argc, char **argv, void (*start)());

// Converts a Program Header type macro into its readable string representation.
const char* get_type_name(Elf32_Word p_type) {
    switch(p_type) {
        case PT_NULL:    return "NULL";
        case PT_LOAD:    return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP:  return "INTERP";
        case PT_NOTE:    return "NOTE";
        case PT_SHLIB:   return "SHLIB";
        case PT_PHDR:    return "PHDR";
        case PT_TLS:     return "TLS";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_GNU_STACK:    return "GNU_STACK";
        case PT_GNU_RELRO:    return "GNU_RELRO";
        default:         return "UNKNOWN";
    }
}

// Formats and prints the details of a single Program Header matching the 'readelf -l' output style.
void print_phdr_details(Elf32_Phdr *phdr, int arg) {
    char flags[4] = {' ', ' ', ' ', '\0'};
    if (phdr->p_flags & PF_R) flags[0] = 'R';
    if (phdr->p_flags & PF_W) flags[1] = 'W';
    if (phdr->p_flags & PF_X) flags[2] = 'E'; 
    
    printf("%-7s 0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %-3s 0x%x\n",
           get_type_name(phdr->p_type),
           phdr->p_offset,
           phdr->p_vaddr,
           phdr->p_paddr,
           phdr->p_filesz,
           phdr->p_memsz,
           flags,
           phdr->p_align);
    
    if (phdr->p_type == PT_LOAD) {
        int prot_flags = 0;
        if (phdr->p_flags & PF_R) prot_flags |= PROT_READ;
        if (phdr->p_flags & PF_W) prot_flags |= PROT_WRITE;
        if (phdr->p_flags & PF_X) prot_flags |= PROT_EXEC;
        int map_flags = MAP_PRIVATE | MAP_FIXED;
        printf("    -> Protection flags: %d, Mapping flags: 0x%x\n", prot_flags, map_flags);
    }
}

// Iterates over all ELF program headers and applies a given callback function to each.
int foreach_phdr(void *map_start, void (*func)(Elf32_Phdr *, int), int arg) {
    Elf32_Ehdr *elf_header = (Elf32_Ehdr *)map_start;
    Elf32_Phdr *phdr_table = (Elf32_Phdr *)((char *)map_start + elf_header->e_phoff);
    for (int i = 0; i < elf_header->e_phnum; i++) {
        func(&phdr_table[i], arg);
    }
    return 0;
}

// Maps a PT_LOAD segment from the ELF file into virtual memory using mmap with proper alignment and protection flags.
void load_phdr(Elf32_Phdr *phdr, int fd) {
     if (phdr->p_type != PT_LOAD) 
        return;
    int prot_flags = 0;
    if (phdr->p_flags & PF_R) prot_flags |= PROT_READ;
    if (phdr->p_flags & PF_W) prot_flags |= PROT_WRITE;
    if (phdr->p_flags & PF_X) prot_flags |= PROT_EXEC;
    int map_flags = MAP_PRIVATE | MAP_FIXED;
    Elf32_Addr vaddr = phdr->p_vaddr & 0xfffff000;
    Elf32_Off offset = phdr->p_offset & 0xfffff000;
    int padding = phdr->p_vaddr & 0xfff;
    int size = phdr->p_memsz + padding;
    void *mapped_mem = mmap((void *)vaddr, size, prot_flags, map_flags, fd, offset);
    if (mapped_mem == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }
    print_phdr_details(phdr, 0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <elf_file>\n", argv[0]);
        return 1;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        return 1;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0) {
        perror("Failed to get file stats");
        close(fd);
        return 1;
    }
    void *map_start = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        return 1;
    }
    printf("Type    Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align\n");
    foreach_phdr(map_start, load_phdr, fd);
    Elf32_Ehdr *header = (Elf32_Ehdr *)map_start;
    printf("Passing control to the loaded program...\n");
    startup(argc - 1, argv + 1, (void *)(header->e_entry));
    munmap(map_start, file_stat.st_size);
    close(fd);
    return 0;
}