#ifndef __ACCESS_MEMORY__
#define __ACCESS_MEMORY__
#include "elf_core.h"
#include "elf_binary.h"

int address_writable(elf_core_info* core_info, Elf32_Addr address);
int read_raw_data(elf_core_info* core_info, elf_binary_info* bin_info, Elf32_Addr start, char * buf, size_t len);
int addr_in_segment(GElf_Phdr phdr, Elf32_Addr addr);
int get_data_from_core(long int start, long int size, char * note_data);
int address_executable(elf_core_info* core_info, Elf32_Addr address);
int value_of_register(char * reg, Elf32_Addr* value, struct elf_prstatus thread );
int address_segment(elf_core_info* core_info, Elf32_Addr address);
off_t get_offset_from_address(elf_core_info* core_info, Elf32_Addr address);
int get_data_from_specified_file(elf_core_info* core_info, elf_binary_info* bin_info,  Elf32_Addr address, char * buf, size_t buf_size);
int address_segment(elf_core_info* core_info, Elf32_Addr address);
int get_exe_path_from_address(char*path, Elf32_Addr addr, elf_binary_info* bin_info);

#endif
