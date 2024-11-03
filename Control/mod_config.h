#ifndef MOD_CONFIG_H
#define MOD_CONFIG_H
#include "../Head/stdafx.h"
#include "../Rule/RuleParser.h"

// define statements
#define CONFIG_FILE "/etc/firemod_config"
#define DEFAULT_CONFIG "[]"
// structs

typedef struct
{
        unsigned char *data;
        size_t size;
} file_data;

// Current configuration storage
extern struct mutex current_config_mutex; // Protects the current config file

extern struct mutex current_running_mutex; // Protects the tables -- running data
extern fire_Rule *running_table_in;
extern int running_table_in_amount;
extern fire_Rule *running_table_out;
extern int running_table_out_amount;

// functions

int save_new_config(file_data *file_content);
void print_config_safe(void);
static int check_config_file(void);
file_data *load_config_file_data(void);
static int reset_config(void); // set to ""
int set_default_config_file_data(void);
int delete_config_file(void);
file_data *read_entire_file(struct file *filp);
void free_file_data(file_data *file_content);
void init_config_file(void);
void cleanup_config(void);

#endif