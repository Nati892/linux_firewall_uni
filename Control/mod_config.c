#include "mod_config.h"
// Define the variables here
struct mutex current_config_mutex;
struct mutex current_config_pending_change_mutex;
struct mutex current_running_mutex;
fire_Rule *running_table_in;
int running_table_in_amount;
fire_Rule *running_table_out;
int running_table_out_amount;
file_data pending_config;

// Helper function for root credentials
static struct file *root_filp_open(const char *path, int flags, umode_t mode)
{
    struct file *filp;
    const struct cred *old_cred;
    struct cred *new_cred;

    new_cred = prepare_creds();
    if (!new_cred) {
        return ERR_PTR(-ENOMEM);
    }

    // Set root ownership
    new_cred->fsuid = GLOBAL_ROOT_UID;
    new_cred->fsgid = GLOBAL_ROOT_GID;

    // Install new credentials
    commit_creds(new_cred);
    
    filp = filp_open(path, flags, mode);
    
    return filp;
}


int delete_file(char *path) 
{
    struct file *check;
    
    shared_print("delete file: checking full path: %s\n", path);
    
    // Check file with root credentials
    check = root_filp_open(path, O_RDONLY, 0);
    if (IS_ERR(check)) {
        long err = PTR_ERR(check);
        shared_print("delete file: config file check failed, error: %ld\n", err);
        if (err == -ENOENT) {
            shared_print("delete file: the config file does not exist\n");
        } else if (err == -EACCES) {
            shared_print("delete file: permission denied accessing config file\n");
        }
        return err;
    }
    
    shared_print("delete file: config file exists and is accessible\n");
    filp_close(check, NULL);

    // Try to delete the file with root credentials
    check = root_filp_open(path, O_WRONLY | O_TRUNC, 0);
    if (!IS_ERR(check)) {
        filp_close(check, NULL);
        shared_print("delete file: successfully truncated file\n");
        return 0;
    }
    
    return PTR_ERR(check);
}

void print_current_file_contents(const char *context)
{
        struct file *filp;
        file_data *content;

        shared_print("%s: Reading current file contents...\n", context);

        filp = filp_open(CONFIG_FILE_PATH, O_RDONLY, 0);
        if (IS_ERR(filp))
        {
                shared_print("%s: Failed to open config file for reading\n", context);
                return;
        }

        content = read_entire_file(filp);
        filp_close(filp, NULL);

        if (content)
        {
                shared_print("%s: Current file contents (%d bytes): %.*s\n",
                             context, content->size, content->size, (char *)content->data);
                free_file_data(content);
        }
        else
        {
                shared_print("%s: Failed to read file contents\n", context);
        }
}

void validate_pending_config(void)
{
        file_data new_data;

        shared_print("timer: checking pending config\n");

        mutex_lock(&current_config_pending_change_mutex);

        if (pending_config.data == NULL || pending_config.size <= 0)
        {
                shared_print("validate_pending_config: no pending config found");
                mutex_unlock(&current_config_pending_change_mutex);
                return;
        }

        shared_print("validate_pending_config: found config to apply of size %d\n", pending_config.size);

        // Take ownership of the pending data
        new_data.data = pending_config.data;
        new_data.size = pending_config.size;

        // Clear pending config
        pending_config.data = NULL;
        pending_config.size = 0;

        mutex_unlock(&current_config_pending_change_mutex);

        // Process the config
        shared_print("timer: processing pending config\n");
        save_new_config(&new_data);

        // Clean up
        kfree(new_data.data);
}

// Modified save_new_config to use root credentials
int save_new_config(file_data *data)
{
        struct file *filp;
        loff_t pos = 0;
        int ret;

        shared_print("SAVE_NEW_CONFIG FUNCTION CALLED\n");

        if (!data || !data->data || data->size <= 0)
        {
                shared_print("config: Invalid configuration data\n");
                return -EINVAL;
        }

        shared_print("config: Attempting to write data (%d bytes): %.*s\n",
                     data->size, data->size, (char *)data->data);

        // First verify the new configuration is valid
        fire_Rule *table_in = NULL;
        int in_amount = 0;
        fire_Rule *table_out = NULL;
        int out_amount = 0;

        if (ParseRules(data->data, data->size, &table_in, &in_amount,
                       &table_out, &out_amount) == fire_FALSE)
        {
                shared_print("config: Invalid configuration format\n");
                return -EINVAL;
        }

        shared_print("config: Parsed new config successfully: in=%d, out=%d\n",
                     in_amount, out_amount);

        mutex_lock(&current_config_mutex);

        // Delete existing file first using root credentials
        ret = delete_file(CONFIG_FILE_PATH);
        if (ret != 0)
        {
                shared_print("config: Warning - could not delete old config file, error %d\n", ret);
        }

        // Create new file with root credentials
        filp = root_filp_open(CONFIG_FILE_PATH2, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (IS_ERR(filp))
        {
                mutex_unlock(&current_config_mutex);
                shared_print("config: Failed to create new config file, error %ld\n", PTR_ERR(filp));
                kfree(table_in);
                kfree(table_out);
                return PTR_ERR(filp);
        }

        ret = kernel_write(filp, data->data, data->size, &pos);
        filp_close(filp, NULL);

        if (ret < 0)
        {
                mutex_unlock(&current_config_mutex);
                shared_print("config: Failed to write to config file, error %d\n", ret);
                kfree(table_in);
                kfree(table_out);
                return ret;
        }

        mutex_unlock(&current_config_mutex);

        // Update running configuration
        mutex_lock(&current_running_mutex);
        kfree(running_table_in);
        kfree(running_table_out);
        running_table_in = table_in;
        running_table_in_amount = in_amount;
        running_table_out = table_out;
        running_table_out_amount = out_amount;
        mutex_unlock(&current_running_mutex);

        shared_print("config: New configuration saved and applied successfully\n");
        print_config_safe();
        print_current_file_contents("save_new_config");

        return 0;
}

void print_config_safe(void)
{
        mutex_lock(&current_running_mutex); // Upadte the tables
        shared_print("config: in amount %d\n", running_table_in_amount);
        shared_print("config: out amount %d\n", running_table_out_amount);
        mutex_unlock(&current_running_mutex);
}
int parse_file_data_safe(file_data *conf)
{
        fire_Rule *table_in = NULL;
        int in_amount = 0;
        fire_Rule *table_out = NULL;
        int out_amount = 0;

        if (conf == NULL || conf->size <= 0)
                return -1;

        fire_BOOL success_res = ParseRules(conf->data, conf->size, &table_in, &in_amount, &table_out, &out_amount);

        if (success_res == fire_FALSE)
        {
                return -1;
        }

        mutex_lock(&current_running_mutex); // Upadte the tables
        running_table_in = table_in;
        running_table_in_amount = in_amount;
        running_table_out = table_out;
        running_table_out_amount = out_amount;
        mutex_unlock(&current_running_mutex);

        print_config_safe();

        return 0;
}
// Generic function to read entire file into memory
file_data *read_entire_file(struct file *filp)
{
        file_data *file_content;
        loff_t file_size;
        loff_t pos = 0;
        int ret;

        if (!filp || IS_ERR(filp))
        {
                shared_print("file: Invalid file pointer\n");
                return NULL;
        }

        file_content = kmalloc(sizeof(*file_content), GFP_KERNEL);
        if (!file_content)
        {
                shared_print("file: Failed to allocate file_data structure\n");
                return NULL;
        }

        file_size = vfs_llseek(filp, 0, SEEK_END);
        if (file_size < 0)
        {
                shared_print("file: Failed to get file size\n");
                shared_free(file_content);
                return NULL;
        }

        vfs_llseek(filp, 0, SEEK_SET);

        file_content->data = kmalloc(file_size, GFP_KERNEL);
        if (!file_content->data)
        {
                shared_print("file: Failed to allocate memory for file data\n");
                shared_free(file_content);
                return NULL;
        }

        ret = kernel_read(filp, file_content->data, file_size, &pos);
        if (ret < 0)
        {
                shared_print("file: Failed to read file\n");
                shared_free(file_content->data);
                shared_free(file_content);
                return NULL;
        }

        file_content->size = ret;
        return file_content;
}

void free_file_data(file_data *file_content)
{
        if (file_content)
        {
                shared_free(file_content->data);
                shared_free(file_content);
        }
}

// Load config file data
file_data *load_config_file_data(void)
{
        struct file *filp;
        file_data *content = NULL;

        filp = filp_open(CONFIG_FILE_PATH, O_RDONLY | O_CREAT, 0644);
        if (IS_ERR(filp))
        {
                shared_print("config: Failed to open config file\n");
                return NULL;
        }

        content = read_entire_file(filp);
        filp_close(filp, NULL);

        if (content)
        {
                shared_print("config: Loaded %zu bytes\n", content->size);
        }

        return content;
}

int delete_config_file(void)
{
        struct file *filp;

        filp = filp_open(CONFIG_FILE_PATH, O_WRONLY | O_CREAT, 0644);
        if (IS_ERR(filp))
        {
                if (PTR_ERR(filp) == -ENOENT)
                {
                        // File doesn't exist, that's fine
                        return 0;
                }
                shared_print("config: Failed to open file for deletion\n");
                return PTR_ERR(filp);
        }

        filp_close(filp, NULL);
        shared_print("config: File cleared successfully\n");
        return 0;
}

// Create config with default data
int set_default_config_file_data(const char *def_conf_path, const char *def_conf_data)
{
        struct file *filp;
        loff_t pos = 0;
        int ret;

        shared_print("set_default_config_file_data called");
        
        // Create file with root credentials and restricted permissions
        filp = root_filp_open(def_conf_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (IS_ERR(filp))
        {
                shared_print("config: Failed to create config file, error %ld\n", PTR_ERR(filp));
                return PTR_ERR(filp);
        }

        ret = kernel_write(filp, def_conf_data, strlen(def_conf_data), &pos);
        filp_close(filp, NULL);

        if (ret < 0)
        {
                shared_print("config: Failed to write default config, error %d\n", ret);
                return ret;
        }

        shared_print("config: Created default config file at %s with root ownership\n", def_conf_path);
        return 0;
}

static int check_config_file(void)
{
        file_data *content;
        int ret;

        // Try to load existing config
        content = load_config_file_data();
        if (content)
        {
                shared_print("config: FUCK YEAH!\n");
                shared_print("config: Content: %.*s\n",
                             (int)content->size, content->data);
                free_file_data(content);
                return 0;
        }

        // No config exists, create default
        ret = set_default_config_file_data(CONFIG_FILE_PATH, DEFAULT_CONFIG);
        if (ret < 0)
        {
                return ret;
        }

        return 0;
}

// Example of how to reset config to default
static int reset_config(void)
{
        int ret;

        ret = delete_config_file();
        if (ret < 0)
        {
                return ret;
        }

        return set_default_config_file_data(CONFIG_FILE_PATH, DEFAULT_CONFIG);
}

void init_config_file(void)
{
        file_data *config;
        int ret = 0;
        bool need_default = false;

        // init global variables
        running_table_in = NULL;
        running_table_in_amount = 0;
        running_table_out = NULL;
        running_table_out_amount = 0;
        pending_config.data = NULL;
        pending_config.size = 0;
        mutex_init(&current_config_mutex);
        mutex_init(&current_running_mutex);
        mutex_init(&current_config_pending_change_mutex);
        // First try to load existing config
        config = load_config_file_data();
        if (config != NULL)
        {
                // Config exists, try to use it
                ret = parse_file_data_safe(config);
                free_file_data(config);

                if (ret != 0)
                {
                        delete_config_file();
                        need_default = true;
                }
                else
                {
                        // Config is good
                        shared_print("config: Existing config loaded and validated\n");
                        return;
                }
        }
        else
        {
                // No config exists
                need_default = true;
        }

        if (need_default)
        {
                // Create default config
                ret = set_default_config_file_data(CONFIG_FILE_PATH, DEFAULT_CONFIG);
                if (ret < 0)
                {
                        shared_print("config: Failed to create default config\n");
                        return;
                }

                // Load and verify the default config
                config = load_config_file_data();
                if (!config)
                {
                        shared_print("config: Failed to load default config\n");
                        return;
                }

                ret = parse_file_data_safe(config);
                if (ret != 0)
                {
                        shared_print("config: Default config validation failed\n");
                }
                else
                {
                        shared_print("config: Default config loaded and validated\n");
                }

                free_file_data(config);
        }
}

void cleanup_config(void)
{
        mutex_destroy(&current_config_mutex);
        mutex_destroy(&current_running_mutex);
        mutex_destroy(&current_config_pending_change_mutex);
}