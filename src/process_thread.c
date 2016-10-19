#include <stdio.h>
#include <libdis.h>
#include "elf_binary.h"
#include "access_memory.h"
#include "disassemble.h"
#include "thread_selection.h"

int pc_executable(elf_core_info* core_info, struct elf_prstatus thread){
	int exec = 1;
	Elf32_Addr address; 
	address = thread.pr_reg[EIP]; 
	if (!address_executable(core_info, address)){
#ifdef LOG_STATE
		fprintf(stdout, "STATE: The PC value 0x%x of thread is illegal\n", (unsigned int)address);
#endif
		exec = 0;	
	}
	return exec;
}

int single_op_legal_access(x86_insn_t *insn, unsigned op_num, struct elf_prstatus thread, elf_core_info* core_info){
	int legal = 1;
	x86_ea_t* ea;
	Elf32_Addr base, index, target;
	int scale;
	x86_op_t *op;

	switch(op_num){
	case 0:
		if ((op = x86_operand_1st(insn)) && !(op->flags & op_implied))
			break;
		return 1;
	case 1:
		if ((op = x86_operand_2nd(insn)) && !(op->flags & op_implied) )
			break;
		return 1;
	case 2:
		if ((op = x86_operand_3rd(insn)))
			break;	
		return 1;
	default: 
		return 1;
	}
	
	switch(op->type){
	case op_expression:
		ea = &op->data.expression;
		if (ea->base.name[0]){
			if (value_of_register(ea->base.name, &base, thread))
				target = base; 
			else 
				break;
	        if (ea->index.name[0]) {
				if(value_of_register(ea->index.name, &index, thread)){
					target+=index * (unsigned int) ea->scale; 
				}else{
					break;
                }
			}
			if (address_segment(core_info, target)<0){
				legal = 0;
				break;
			}
			if ((insn->type == insn_mov) && (op_num == 0) && !address_writable(core_info, target)){
				legal = 0;
				break;
			}
		}
	default: 
		break;
	}
	return legal;
}

int op_legal_access(x86_insn_t *insn, struct elf_prstatus thread, elf_core_info* core_info){
	unsigned i = 0; 
	for (i=0; i<3; i++)
		if (!single_op_legal_access(insn, i, thread,core_info))
			return 0;
	return 1;
}

int pc_legal_access(elf_core_info* core_info, elf_binary_info *bin_info, struct elf_prstatus thread){
	int legal_access; 
	Elf32_Addr address;
	int offset;
	char inst_buf[INST_LEN];
	x86_insn_t inst; 

	address = thread.pr_reg[EIP];
	offset = get_offset_from_address(core_info, address);

	if (offset == ME_NMAP || offset == ME_NMEM){
#ifdef DEBUG
		fprintf(stdout, "DEBUG: The offset of this pc cannot be obtained\n");
#endif
		return 0;
	}
	
	if (offset == ME_NDUMP){
		if (get_data_from_specified_file(core_info, bin_info, address, inst_buf, INST_LEN) < 0)
            return 0;
	}

	if (offset >= 0)
		get_data_from_core((Elf32_Addr)offset, INST_LEN, inst_buf);
	
	if (disasm_one_inst(inst_buf, INST_LEN, 0, &inst) < 0){
#ifdef DEBUG
		fprintf(stdout, "DEBUG: The PC points to an error position\n");
#endif
		return 0;
	}
#if defined(DEBUG) || defined(LOG_STATE)
	fprintf(stdout, "Evidence: The PC value is 0x%x\n", (unsigned)address);
	char line[64];
	x86_format_insn(&inst, line, 64, intel_syntax);	
	fprintf(stdout, "Evidence: The instruction to which PC points is %s. It Is Accessing Illegal Address\n", line);
#endif
	if (!op_legal_access(&inst, thread, core_info)){
		return 0;
	}
	return 1; 
}

int is_thread_crash(elf_core_info* core_info, elf_binary_info* bin_info, struct elf_prstatus thread){
	int crash  = 0;

	if (!pc_executable(core_info, thread)){
		crash = 1;
		goto out;
	}

	if (!pc_legal_access(core_info,bin_info, thread)){
		crash = 1;
		goto out;
	}
out:
	return crash;
}

// select the thread that leads to crash
// this will be the first step of analysis
int select_thread(elf_core_info* core_info, elf_binary_info * bin_info){
	int crash_num = -1;
	int thread_num = core_info -> note_info->core_thread.thread_num;
	int i = 0;	
#ifdef LOG_STATE
	fprintf(stdout, "STATE: Determining The Thread Leading To Crash\n");
#endif

    // multiple threads exist		
    for (i=0; i<thread_num; i++){
	    if (is_thread_crash(core_info, bin_info, core_info->note_info->core_thread.threads_status[i])){
		    crash_num = i;
		    break;
	    }
    }

#ifdef DEBUG
	if (crash_num == -1)
		fprintf(stderr, "Error: Could not determine the crash thread\n");
	else
		fprintf(stdout, "DEBUG: The number of the crashing thread is %d\n", crash_num);
#endif
	return crash_num;
}
