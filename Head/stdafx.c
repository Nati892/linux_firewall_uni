#include "stdafx.h"


#ifdef __KERNEL__
// Code that is compiled in the kernel space
void shared_free(void *ptr) {
    kfree(ptr);
}

void* shared_malloc(size_t size) {
    return kmalloc(size, GFP_KERNEL);
}

void shared_print(const char *fmt, ...) {
    va_list args;
    char buf[256]; // Buffer for formatted output
    
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args); // Format the string
    va_end(args);
    
    // Prepend KERN_INFO and print
    printk(KERN_INFO "firemod: %s", buf);
}

#else
// Code that is compiled in user space
void shared_free(void *ptr) {
    free(ptr);
}

void* shared_malloc(size_t size) {
    return malloc(size);
}

void shared_print(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    // Check if the format string ends with a newline
    size_t len = strlen(fmt);
    char *buffer;

    // Allocate enough space for the formatted string plus a newline
    buffer = (char *)malloc(len + 20); // +1 for \n and +1 for \0

    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        va_end(args);
        return;
    }

    // Format the string
    vsnprintf(buffer, len + 1, fmt, args);

    // Append newline if not already present
    if (buffer[len - 1] != '\n') {
        buffer[len] = '\n'; // Add newline at the end
        buffer[len + 1] = '\0'; // Null-terminate the string
    } else {
        buffer[len] = '\0'; // Just null-terminate if already ends with newline
    }

    // Print the final string
    vprintf(buffer, args);

    free(buffer);
    va_end(args);
}

#endif // __KERNEL__
