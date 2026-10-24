# ELF Binary Tools

Three low-level tools in C for working with Linux binaries (32-bit ELF). I built them in the Extended System Programming Lab at Ben-Gurion University.

| Folder | What it does |
|---|---|
| `loader/` | Loads an ELF executable into memory with `mmap` and runs it |
| `elf-analyzer/` | Reads ELF object files (similar to `readelf`) and merges two of them |
| `virus-scanner/` | Finds virus signatures in a binary file and neutralizes them |

---

## loader

A minimal ELF loader. Instead of letting the OS load the program, it does it itself:

1. Maps the ELF file with `mmap` and reads the program header table
2. For every `PT_LOAD` segment:
   - aligns the virtual address and file offset to a page boundary
   - converts the segment flags (R/W/X) to `PROT_READ` / `PROT_WRITE` / `PROT_EXEC`
   - maps the segment to its exact virtual address with `mmap` and `MAP_FIXED`
3. Prints the program headers (like `readelf -l`)
4. Passes control to the program's entry point through `startup` (x86 Assembly)

Iterating over the headers is done with `foreach_phdr`, which takes a function pointer and applies it to every program header.

```bash
make
./my_loader <elf_executable> [args...]
```

The loader is linked with a custom linker script (`linking_script`) so that its own code sits at an address that does not collide with the program it loads.

Note: the loader does not zero the part of a segment between `p_filesz` and `p_memsz` (`.bss`).

---

## elf-analyzer

A menu-driven tool for inspecting 32-bit ELF object files. Up to two files can be open at the same time.

- **Examine ELF file**: maps the file with `mmap`, checks the magic bytes and prints the ELF header (entry point, endianness, header table offsets)
- **Print section names**: index, name, address, offset, size and type of every section
- **Print symbols**: value, section and name of every symbol in the symbol table
- **Print relocations**: location, symbol name and type of every relocation entry
- **Check files for merge**: finds symbols that are undefined in both files or defined in both
- **Merge ELF files**: combines two relocatable files into `out.ro`: concatenates `.text`, `.data` and `.rodata`, adds up the `.bss` sizes and writes a new section header table
- **Debug mode**: prints extra details to stderr

```bash
make
./myELF
```

Example:
```bash
gcc -m32 -c a.c -o a.o
gcc -m32 -c b.c -o b.o
./myELF
# F a.o, F b.o, then S / R / C / M
```

---

## virus-scanner

A menu-driven virus detector.

- **Load signatures**: reads a signature file. The magic number (`VIRL` / `VIRB`) tells whether it is little or big endian. Each virus is `[2 bytes size][16 bytes name][signature]` and is stored in a linked list
- **Print signatures**: prints each virus name, size and signature bytes in hex
- **Select file / Detect viruses**: scans the file byte by byte and reports every match with its position
- **Fix file**: neutralizes each detected virus by writing `0xC3` (the x86 `RET` instruction) at its start
- The menu is an array of structs with function pointers

```bash
make
./AntiVirus
```

Limitation: only the first 10,000 bytes of the inspected file are scanned.

---

## Build requirements

All tools are compiled as 32-bit (`-m32`), and the loader's `start.s` is assembled with NASM. On a 64-bit machine:

```bash
sudo apt install gcc-multilib nasm
```

`start.s` and `startup.s` were provided as part of the course.

## Testing

The ELF analyzer and the virus scanner were checked with Valgrind: no memory errors and no leaks.
