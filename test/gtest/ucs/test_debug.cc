/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2012.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <common/test.h>
extern "C" {
#include <ucs/debug/backtrace/base/backtrace.h>
#include <ucs/sys/compiler.h>
#include <ucs/sys/sys.h>
}

#include <algorithm>
#include <dlfcn.h>

class test_debug : public ucs::test_with_param<const char*> {
public:
    virtual void init() {
        modify_config("BACKTRACE_METHODS", GetParam());
    }

    static std::vector<const char*> enum_test_params() {
        // Return vector of supported providers
        std::vector<const char*> result = {"bfd", "unwind", "default"};
        std::remove_if(result.begin(), result.end(), [](const char *name) {
            return ucs_debug_backtrace_find_provider(name) == NULL;
        });
        return result;
    }
};

std::string __basename(const std::string& path) {
    char *p = strdup(path.c_str());
    std::string bn(::basename(p));
    free(p);
    return bn;
}

UCS_TEST_P(test_debug, lookup_address) {
    const char *sym_name = "ucs_log_flush";
    const void *address  = dlsym(RTLD_DEFAULT, sym_name);
    UCS_TEST_MESSAGE << "Expect to find " << sym_name << " at " << address;

    const char *found_name = ucs_debug_get_symbol_name(address);
    EXPECT_EQ(std::string(sym_name), found_name);
}

UCS_TEST_P(test_debug, lookup_invalid) {
    const char *found_name = ucs_debug_get_symbol_name((void*)0xffffffffffff);
    EXPECT_EQ(std::string(UCS_DEBUG_UNKNOWN_SYMBOL), found_name);
}

UCS_TEST_P(test_debug, print_backtrace) {
    char *data;
    size_t size;

    FILE *f = open_memstream(&data, &size);
    ucs_debug_print_backtrace(f, 0, 0);
    fclose(f);

    /* Some functions that should appear */
    EXPECT_TRUE(strstr(data, "print_backtrace") != NULL);
#ifdef HAVE_DETAILED_BACKTRACE
    EXPECT_TRUE(strstr(data, "main") != NULL);
#endif
    printf("%s",data);
    free(data);
}

INSTANTIATE_TEST_SUITE_P(test_debug, test_debug, ::testing::ValuesIn(test_debug::enum_test_params()));