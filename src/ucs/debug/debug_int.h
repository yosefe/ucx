/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2021.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCS_DEBUG_INT_H_
#define UCS_DEBUG_INT_H_


extern const char *ucs_signal_names[];


/**
 * Initialize UCS debugging subsystem.
 */
void ucs_debug_init();


/**
 * Cleanup UCS debugging subsystem.
 */
void ucs_debug_cleanup(int on_error);


/**
 * Disable signal handling in UCS for all signals
 * that was set in ucs_global_opts.error_signals.
 * Previous signal handlers are set.
 */
void ucs_debug_disable_signals();


/**
 * Called when UCS detects a fatal error and provides means to debug the current
 * state of UCS.
 */
void ucs_handle_error(const char *message);

#endif
