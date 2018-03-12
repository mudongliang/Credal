char *core_path;
char *bin_path; 
char *lib_path; 

void set_core_path(char * path){
    core_path = path;
}

char *get_core_path(void){
    return core_path;
}
