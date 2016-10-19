# AdvancedCredal
Advanced Credal

## Prerequirement

    $ sudo apt-get install libelf1 libelf-dev

library to read and write ELF files

    $ sudo apt-get install libdisasm0 libdisasm-dev

disassembler library for x86 code

## Usage

    $ ./main coredump binary_path library_path

### Compile

    $ make

### Test

    $ make test

### Clean

    $ make clean

## Corresponding APIs

- common.c
  - void set_core_path(char * path);
  - char * get_core_path(void);
  - void set_bin_path(char * path);
  - char * get_bin_path(void);
  - void set_lib_path(char * path);
  - char * get_lib_path(void);
- disassemble.c
  - int disasm_one_inst(char * buf, size_t buf_size, int pos,  x86_insn_t* inst);
- access_memory.c
  - int address_writable(elf_core_info* core_info, Elf32_Addr address);
  - int read_raw_data(elf_core_info* core_info, elf_binary_info* bin_info, Elf32_Addr start, char * buf, size_t len);
  - int addr_in_segment(GElf_Phdr phdr, Elf32_Addr addr);
  - int get_data_from_core(long int start, long int size, char * note_data);
  - int address_executable(elf_core_info* core_info, Elf32_Addr address);
  - int value_of_register(char * reg, Elf32_Addr* value, struct elf_prstatus thread );
  - int address_segment(elf_core_info* core_info, Elf32_Addr address);
  - off_t get_offset_from_address(elf_core_info* core_info, Elf32_Addr address);
  - int get_data_from_specified_file(elf_core_info* core_info, elf_binary_info* bin_info,  Elf32_Addr address, char * buf, size_t buf_size);
  - int address_segment(elf_core_info* core_info, Elf32_Addr address);
  - int get_exe_path_from_address(char*path, Elf32_Addr addr, elf_binary_info* bin_info);
- elf_binary.c
  - elf_binary_info* parse_binary(elf_core_info* core_info);
  - int destroy_bin_info(elf_binary_info * bin_info);
- elf_core.c
  - int destroy_core_info(elf_core_info*);
  - elf_core_info* parse_core(char*);
  - int process_segment(Elf*, elf_core_info*);
  - int process_note_segment(Elf*, elf_core_info*);
- thread_selection.c
  - int select_thread(elf_core_info* core_info, elf_binary_info * bin_info);
