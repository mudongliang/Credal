#include <stdio.h>
#include <stdlib.h>
#include "elf_core.h"

int main(int argc, char *argv[]){
    if (argc != 2){
        fprintf(stderr, "Help: %s coredump\n", argv[0]);
        exit(0);
    }
    set_core_path(argv[1]);

    elf_core_info *core_info = parse_core(argv[1]); 
    if(!core_info)
        fprintf(stderr,"The core file is not parsed correctly");

    destroy_core_info(core_info);
}
