#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "elf_core.h"
#include "elf_binary.h"
#include "access_memory.h"

int get_exe_path_from_address(char*path, Elf32_Addr addr, elf_binary_info* bin_info){
	int i; 
	int find = 0;

	for(i=0; i<bin_info->bin_lib_num; i++){
	    if(bin_info->binary_info_set[i].parsed)
		if(addr >= bin_info->binary_info_set[i].base_address && addr < bin_info->binary_info_set[i].end_address ){
			memset(path, 0, FILE_NAME_SIZE);
			memcpy(path, bin_info->binary_info_set[i].bin_name, strlen(bin_info->binary_info_set[i].bin_name));
			find = 1;
			break;
		}
	}

	if(find) return 1; 

	memset(path, 0, FILE_NAME_SIZE);
	return 0;
}

//get the value by the name of register
int value_of_register(char * reg, Elf32_Addr* value, struct elf_prstatus thread){
	int match = 0;
	if(strcmp(reg, "eax") == 0){
		*value = thread.pr_reg[EAX];
		match = 1;
		goto out;
	}
    if(strcmp(reg, "ebx") == 0){
        *value = thread.pr_reg[EBX];
        match = 1;
        goto out;
    }
    // rewrite it with switch case
out: 
	return match; 
}

//determine the segment this address exists.
//if -1, then this address does not exist in any segment. Illegal access!
int address_segment(elf_core_info* core_info, Elf32_Addr address){
	int segment = -1;
	int i = 0;
	for (i=0; i< core_info->phdr_num; i++){
		if(core_info->phdr[i].p_type & PT_LOAD){
			//the following type conversion is to make sure the comparison  makes sense
			//please fixme later
			Elf32_Addr mstart = (Elf32_Addr) core_info->phdr[i].p_vaddr;
			Elf32_Word msize = (Elf32_Word) core_info->phdr[i].p_memsz;
			if(address >= mstart && address < mstart + msize){
				segment = i;
				break;
			} 
		}
	}
	return segment; 
}

//Get the offset of memory in file based on its address
off_t get_offset_from_address(elf_core_info* core_info, Elf32_Addr address){
	off_t offset; 
	int segment; 
	if((segment = address_segment(core_info, address))<0){
		return ME_NMAP;
	}
	if(! (Elf32_Word)core_info->phdr[segment].p_memsz)
		return ME_NMEM;
	//this area is not really mapped into the address space
	if(core_info->phdr[segment].p_memsz != core_info->phdr[segment].p_filesz){
#ifdef DEBUG
		fprintf(stdout, "DEBUG: the memsize is %u, and the file size is %u\n",
                (unsigned int)core_info->phdr[segment].p_memsz, (unsigned int)core_info->phdr[segment].p_filesz);
#endif 
		return ME_NDUMP;
	}
	offset = (Elf32_Off)core_info->phdr[segment].p_offset + address - (Elf32_Addr)core_info->phdr[segment].p_vaddr; 
	return offset; 
}

int get_data_from_core(long int start, long int size, char * note_data){
    int fd;
    if (( fd = open(core_path , O_RDONLY , 0)) < 0){
#ifdef DEBUG
    	fprintf(stderr, "Core file open error %s\n", strerror(errno));
#endif
    	return -1;
    }
    if(lseek(fd, start, SEEK_SET)<0){
    	fprintf(stderr, "Core file lseek error %s\n", strerror(errno));
    	close(fd);
    	return -1;
    }
    if(read(fd, note_data, size)<0){
    	fprintf(stderr, "Core file open error %s\n", strerror(errno));
    	close(fd);
    	return -1;
    }
    close(fd);
    return 0;
}

//determine if the address is executable. 
int address_executable(elf_core_info* core_info, Elf32_Addr address){
	int segment; 
	if((segment = address_segment(core_info, address))<0)
		return 0;
	return (core_info->phdr[segment].p_flags & PF_X) ? 1:0;
}

int address_writable(elf_core_info* core_info, Elf32_Addr address){
        int segment;
        if((segment = address_segment(core_info, address))<0)
                return 0;
        return (core_info->phdr[segment].p_flags & PF_W) ? 1:0;
}

int addr_in_segment(GElf_Phdr phdr, Elf32_Addr addr){
	if(addr >= phdr.p_vaddr && addr < phdr.p_vaddr + phdr.p_memsz)
		return 1;
	return 0;
}

int read_raw_data(elf_core_info* core_info, elf_binary_info* bin_info, Elf32_Addr start, char * buf, size_t len){
	int  offset = get_offset_from_address(core_info, start);
    if(offset == ME_NMAP || offset == ME_NMEM){
#ifdef DEBUG
        fprintf(stdout, "DEBUG: The offset of this pc in memory read cannot be obtained\n");
#endif
        return -1;
    }

    if(offset == ME_NDUMP){
        if(get_data_from_specified_file(core_info, bin_info, start, buf, len)<0)
            return -1;
    }
    if(offset>=0)
        return get_data_from_core((Elf32_Addr)offset, len, buf);
}

//get the memory from the file recorded by the NT_FILE information. 
int get_data_from_specified_file(elf_core_info* core_info, elf_binary_info* bin_info,  Elf32_Addr address, char * buf, size_t buf_size){
	int data_obtained = 0;
	int file_num =-1;
	int phdr_num = -1;
	int i;
	int fd;
	char * file_path;
	Elf32_Addr offset;
	Elf32_Addr reduce = 0;
	individual_binary_info* target_file = 0;

	for(i = 0; i<bin_info->bin_lib_num; i++){
		if(bin_info->binary_info_set[i].parsed)
    		if(address >= bin_info->binary_info_set[i].base_address && address < bin_info->binary_info_set[i].end_address){
			file_num = i;
			break;
		    } 
	}
	if(file_num == -1)
		goto out;

	target_file = &bin_info->binary_info_set[file_num];
	file_path = target_file->bin_name; 

	if(target_file->phdr[0].p_vaddr < target_file->base_address)
		reduce = target_file -> base_address;	

	for(i=0; i<target_file->phdr_num; i++){
		if((address-reduce)>=target_file->phdr[i].p_vaddr &&  (address-reduce) < (target_file->phdr[i].p_vaddr + target_file->phdr[i].p_memsz)){
			phdr_num = i; 
			break;
		}
	}
	if(phdr_num == -1)
		goto out;

#ifdef DEBUG
	fprintf(stdout, "DEBUG: the file mapped to address %u is %s\n", address, file_path);	
#endif
	offset = (address-reduce) - target_file->phdr[phdr_num].p_vaddr +  target_file->phdr[phdr_num].p_offset;

	if (( fd = open ( file_path , O_RDONLY , 0)) < 0){
#ifdef DEBUG
		fprintf(stderr, "Core file open error %s\n", strerror(errno));
#endif
		return -1;
	}
	if(lseek(fd, offset, SEEK_SET)<0){
		fprintf(stderr, "Core file lseek error %s\n", strerror(errno));
		close(fd);
		return -1;
	}
        if(read(fd, buf, buf_size)<0){
		fprintf(stderr, "Core file open error %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
out: 
	return data_obtained;
}
