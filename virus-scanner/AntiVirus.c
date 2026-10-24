#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int is_detected = 0; // Global variable to indicate if a scan was completed, enforcing the rule to detect before fixing
bool LE; // Global variable to indicate file endianness (Little or Big)
FILE *inspect_file = NULL; // Global file pointer to store the file selected for virus inspection
char inspect_file_name[256]; // Stores the path or name of the file currently being inspected
typedef struct virus {
unsigned short SigSize;
unsigned char* VirusName;
unsigned char* Sig;
} virus;

typedef struct link link;
struct link {
link *nextVirus;
virus *vir;
};

// Helper: read signature size with endianness handling (VIRL/VIRB)
static unsigned short readSigSize(FILE *file) {
    unsigned char size_bytes[2];
    // Read 2 bytes; return 0xFFFF on EOF/error
    if (fread(size_bytes, 1, sizeof(size_bytes), file) != sizeof(size_bytes))
        return 0xFFFF;
    
    // Convert: little-endian or big-endian based on LE flag
    if (LE)
        return (unsigned short)(size_bytes[0] | (size_bytes[1] << 8));
    else
        return (unsigned short)((size_bytes[0] << 8) | size_bytes[1]);
}

// Read one virus from file: [2B size] [16B name] [SizeB signature]
// Returns virus struct pointer or NULL on EOF/error
virus* readVirus(FILE* file) {
    // Read signature size; 0xFFFF = EOF or error
    unsigned short sig_size = readSigSize(file);
    if (sig_size == 0xFFFF)
        return NULL;
    
    // Allocate virus struct
    virus *v = (virus*)malloc(sizeof(virus));
    if (v == NULL)
        return NULL;
    
    // Allocate and read 16-byte virus name field
    v->SigSize = sig_size;
    v->VirusName = (unsigned char*)malloc(16);
    if (v->VirusName == NULL) {
        free(v);
        return NULL;
    }
    v->Sig = NULL;
    
    if (fread(v->VirusName, 1, 16, file) != 16) {
        free(v->VirusName);
        free(v);
        return NULL;
    }
    v->VirusName[15] = '\0'; // Ensure null termination
    
    // Allocate and read signature bytes
    if (sig_size > 0) {
        v->Sig = (unsigned char*)malloc(sig_size);
        if (v->Sig == NULL) {
            free(v->VirusName);
            free(v);
            return NULL;
        }
        if (fread(v->Sig, 1, sig_size, file) != sig_size) {
            free(v->Sig);
            free(v->VirusName);
            free(v);
            return NULL;
        }
    }
    
    return v;
}

// Print virus info: name, size, and signature bytes in hex (16 per line)
void printVirus(virus* virus, FILE* output) {
    if (virus == NULL || output == NULL)
        return;
    
    fprintf(output, "Virus name: %s\n", virus->VirusName);
    fprintf(output, "Virus size: %u\n", virus->SigSize);
    fprintf(output, "signature:\n");
    
    // Print signature bytes as hex, max 16 per line
    for (unsigned short i = 0; i < virus->SigSize; i++) {
        fprintf(output, "%02X", virus->Sig[i]);
        if (i + 1 < virus->SigSize)
            fprintf(output, " ");
        if ((i + 1) % 16 == 0 || i + 1 == virus->SigSize)
            fprintf(output, "\n");
    }
    fprintf(output, "\n");
}

// Print the data of every link in list to the given stream
void list_print(link *virus_list, FILE* file){
    while (virus_list != NULL)
    {
        printVirus(virus_list->vir, file);
        virus_list = virus_list->nextVirus;
    }
}

// Add a new link with the given data to the list and return a pointer to the list
link* list_append(link* virus_list, virus* data){
    link* new_link = (link*)malloc(sizeof(link));
    if(new_link == NULL)
        return virus_list;
    else {
        new_link->vir = data;
        new_link->nextVirus = virus_list;
        return new_link;    
    }
}

// Free the memory allocated by the list
void list_free(link *virus_list) {
    link* curr = virus_list;
    link* next_link = virus_list;
    while (curr != NULL)
    {
        next_link = curr->nextVirus;
        if(curr->vir != NULL) {
            free(curr->vir->VirusName);
            free(curr->vir->Sig); 
            free(curr->vir);
        }
        free(curr);
        curr = next_link;
    }
}

// Reads virus signatures from a user-specified file, appends them to the linked list, and returns the new head
link* load_signatures(link* list) {
    char buffer[256];
    printf("Enter signature file name:\n");
    if(fgets(buffer, sizeof(buffer), stdin) == NULL) 
        return list;
    char name[256];
    sscanf(buffer, "%s", name);
    FILE *file = fopen(name, "rb");
    if(file == NULL) {
        fprintf(stderr, "Error: cannot open input file %s\n", name);
        return list;
    }       
    unsigned char magic_number[4];
    fread(magic_number, 1, sizeof(magic_number), file);
    if(memcmp(magic_number, "VIRL", 4) == 0)
        LE = true;
    else if(memcmp(magic_number, "VIRB", 4) == 0)
        LE = false;
    else {
        fprintf(stderr, "Error: Invalid magic number!\n");
        fclose(file); 
        return list;
    }
    virus* v = readVirus(file);
     while (v != NULL) {
        list = list_append(list, v);
        v = readVirus(file);
     }
    fclose(file);
    is_detected = 0;
    return list;
}

// Iterates through the linked list, prints each virus signature, and returns the list
link* print_signatures(link* list) { 
    list_print(list, stdout);
    return list;
}

// Prompts user for file name and opens it for inspection
link* select_file(link* list) {
    char buffer[256];
    printf("Enter file name to inspect:\n");
    if(fgets(buffer, sizeof(buffer), stdin) == NULL) 
        return list;
    char name[256];
    sscanf(buffer, "%s", name);
    
    // Close previous file if open
    if(inspect_file != NULL) {
        fclose(inspect_file);
        inspect_file = NULL;
    }
    
    // Try to open the new file
    FILE *file = fopen(name, "rb");
    if(file == NULL) {
        fprintf(stderr, "Error: cannot open inspect file %s\n", name);
        inspect_file_name[0] = '\0';
        return list;
    }
    
    // Store file pointer and name for later use
    inspect_file = file;
    strcpy(inspect_file_name, name);
    is_detected = 0; 
    return list;
}

// Helper: scan buffer for viruses and print detections
void detect_virus(char *buffer, unsigned int size, link *virus_list) {
    link *curr = virus_list;
    while (curr != NULL) {
        // Skip if virus signature is larger than buffer
        if (size < curr->vir->SigSize) {
            curr = curr->nextVirus;
            continue;
        }
        
        // Scan each position in buffer for this virus signature
        for (unsigned int i = 0; i <= size - curr->vir->SigSize; i++) {
            if (memcmp(&buffer[i], curr->vir->Sig, curr->vir->SigSize) == 0) {
                // Found virus at position i
                printf("Found virus: %s at position %u with size %u\n", 
                       curr->vir->VirusName, i, curr->vir->SigSize);
            }
        }
        curr = curr->nextVirus;
    }
}

// Read file content and scan for viruses
link* detect_viruses(link* list) {
    // Check if file was selected
    if (inspect_file_name[0] == '\0') {
        fprintf(stderr, "Error: no file selected\n");
        return list;
    }
    
    // Reopen file if not currently open
    if (inspect_file == NULL) {
        inspect_file = fopen(inspect_file_name, "rb");
        if (inspect_file == NULL) {
            fprintf(stderr, "Error: cannot open inspect file %s\n", inspect_file_name);
            return list;
        }
    }
    
    // Read file content into buffer
    char buffer[10000];
    unsigned int size = fread(buffer, 1, 10000, inspect_file);
    
    if (size == 0) {
        fprintf(stderr, "Error: cannot read inspect file\n");
        fclose(inspect_file);
        inspect_file = NULL;
        return list;
    }
    
    // Scan for viruses
    detect_virus(buffer, size, list);
    
    // Close file and mark detection complete
    fclose(inspect_file);
    inspect_file = NULL;
    is_detected = 1;
    return list;
}

// Opens the specified file and overwrites the virus signature at the given offset with a RET instruction (0xC3)
void neutralize_virus(char *fileName, int signatureOffset){
    FILE *file = fopen(fileName, "r+b");
    unsigned char ret = 0xC3; //Machine code instruction used to exit the function immediately
    if(file == NULL) {
        fprintf(stderr, "Error: cannot open file\n");
        return;
    }    
    if(fseek(file, signatureOffset, SEEK_SET) !=0) {
        fprintf(stderr, "Error during fseek\n");
        fclose(file);
        return;
    }
    size_t item_written = fwrite(&ret, 1, 1, file);
    if(item_written != 1) 
        fprintf(stderr, "Error during fwrite\n");
    fclose(file);
}

// Scans the infected file, detects all known viruses from the list, and neutralizes them automatically
link* fix_file(link* list) { 
    if(is_detected == 0) {
        fprintf(stderr, "Error: cannot fix before detects\n");
        return list;
    }
    if(inspect_file != NULL) {
        fclose(inspect_file);
        inspect_file = NULL;
    }
    inspect_file = fopen(inspect_file_name, "rb");
    if(inspect_file == NULL) {
        fprintf(stderr, "Error: cannot open inspect file %s\n", inspect_file_name);
        return list;
    }       
    char buffer[10000];  
    unsigned int size = fread(buffer, 1, 10000, inspect_file);
    fclose(inspect_file);
    inspect_file = NULL;
    if(size == 0) {
        fprintf(stderr, "Error: cannot read inspect file\n");
        return list;
    }
    link* curr = list;
    while (curr != NULL) { 
        if (size < curr->vir->SigSize) {
                 curr = curr->nextVirus; 
                 continue;               
        }
        for(unsigned int i=0; i <= size -curr->vir->SigSize; i++) {
                if(memcmp(&(buffer[i]), curr->vir->Sig, curr->vir->SigSize) == 0) {
                    neutralize_virus(inspect_file_name, i);
                }
            }
        curr = curr->nextVirus;   
    }
    is_detected = 0;  
    inspect_file = fopen(inspect_file_name, "rb");
    if(inspect_file == NULL) 
        fprintf(stderr, "Error: cannot open inspect file %s\n", inspect_file_name);
    return list;
}

// Frees all memory allocated for the virus list and safely terminates the program
link* quit(link* list) {
    if(inspect_file != NULL) {
        fclose(inspect_file);
        inspect_file = NULL;
        inspect_file_name[0] = '\0';
    }
    list_free(list);
    exit(0);
    return NULL;
}
struct fun_desc {
    char *name;
    char index;
    link* (*fun)(link*);
};
    struct fun_desc menu[] ={
        {"load signatures", 'L', load_signatures},
        {"print signatures", 'P', print_signatures},
        {"select file to inspect", 'S', select_file},
        {"detect viruses", 'D', detect_viruses},
        {"fix file", 'F', fix_file},
        {"quit", 'Q', quit},
        {NULL, 0, NULL}};


int main(int argc, char **argv)
{ 
    char buffer[256];
    link* list = NULL;
    char choice_index; //Stores the specific character the user chose from the menu
    link* (*choice_fun)(link*); //A function pointer to store the function associated with the user's choice
    bool found; //A flag used to indicate if the user's input matches a valid menu option
    while (1)
    {
        found = false;
        printf("Select operation from the following menu: \n");
        for(int i=0; menu[i].name!=NULL; i++) 
           printf("to %s select: %c\n", menu[i].name, menu[i].index);
        printf("select function according to the index: \n");
        do {
          if(fgets(buffer, sizeof(buffer), stdin) == NULL) 
            quit(list);
        } while(sscanf(buffer, " %c", &choice_index) != 1);
          for(int i=0; menu[i].name!=NULL && !found; i++) {   
            if(choice_index == menu[i].index) {
                found = true; 
                choice_fun = menu[i].fun;
            }
        }
        if(!found)
            printf("function not supported \n");
        else
            list = choice_fun(list); 
    }
    return 0;
}