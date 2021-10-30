/**
 * Copyright (C) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCS_BACKTRACE_H
#define UCS_BACKTRACE_H

#include <ucs/datastruct/list.h>
#include <ucs/type/status.h>
#include <stdio.h>


/* Maximal number of frames in the backtrace */
#define UCS_DEBUG_BACKTRACE_MAX_FRAMES 128

/* Maximal length of a debug symbol */
#define UCS_DEBUG_BACKTRACE_MAX_SYMBOL_LEN 128

/* Return value when a symbol is not found */
#define UCS_DEBUG_UNKNOWN_SYMBOL "???"


typedef enum {
    UCS_DEBUG_BACKTRACE_PRINT_FLAG_SHOW_SOURCE = UCS_BIT(0),
} ucs_debug_print_backtrace_flags_t;


/**
 * @brief Callback function for backtrace
 *
 * @return UCS_OK    - continue the backtrace
 *         otherwise - stop the backtrace and return the error code to caller
 */
typedef ucs_status_t (*ucs_debug_backtrace_frame_cb_t)(
        void *arg, const void *address, const char *function_name,
        ptrdiff_t offset, const char *source_file, unsigned source_line);


/**
 * @brief Callback for retrieving a symbol name by address.
 *
 * @param address   Find the symbol of this address
 * @param buffer    Buffer to store the symbol name
 * @param max       Maximal capacity of the buffer
 *
 * @return Whether the symbol was found.
 */
typedef int (*ucs_debug_get_symbol_name_func_t)(const void *address,
                                                char *buffer, size_t max);


typedef ucs_status_t (*ucs_debug_get_backtrace_func_t)(
        ucs_debug_backtrace_frame_cb_t frame_cb, void *arg);


typedef struct {
    const char                       *name;
    ucs_debug_get_symbol_name_func_t get_symbol_name;
    ucs_debug_get_backtrace_func_t   get_backtrace;
    ucs_list_link_t                  list;
} ucs_debug_backtrace_provider_t;


/* Global list of backtrace providers */
extern ucs_list_link_t ucs_debug_backtrace_providers;


/* Global initialization of debug backtrace */
void ucs_debug_backtrace_init();


/* Global cleanup of debug backtrace */
void ucs_debug_backtrace_cleanup();


/* Find a backtrace provider by name */
ucs_debug_backtrace_provider_t *
ucs_debug_backtrace_find_provider(const char *name);


/**
 * @return Name of a symbol which begins in the given address, or NULL if
 * not found.
 */
const char *ucs_debug_get_symbol_name(const void *address);


/**
 * Print backtrace to an output stream.
 *
 * @param stream         Stream to print to.
 * @param strip          How many frames to strip.
 * @param flags          @ref ucs_debug_print_backtrace_flags_t
 */
void ucs_debug_print_backtrace(FILE *stream, unsigned strip, unsigned flags);


/**
 * @brief Set the pointer to signal restorer function, to be filtered-out from
 * backtrace prints.
 *
 * @param sa_restorer   Pointer to the signal restorer function.
 */
void ucs_debug_set_sa_restorer(const void *sa_restorer);


/**
 * Default implementation of getting symbol name by address.
 * See @ref ucs_debug_get_symbol_name_func_t for details.
 */
int ucs_debug_get_symbol_name_default(const void *address, char *buffer,
                                      size_t max);

#endif