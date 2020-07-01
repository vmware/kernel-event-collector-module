///
/// @file    findsyms.c
///
/// @brief   Implementation of routines for finding the addresses of global
///          function tables that will be hooked by the proxy.
///
/// @copyright (c) 2016 Carbon Black, Inc. All rights reserved.
///

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include "priv.h"
#include "findsyms.h"
#include "mem-cache.h"


#define CB_APP_NAME CB_APP_PROC_DIR

#define CB_KALLSYMS_BUFFER   2048

// kptr_restrict contains 0, 1 or 2
#define KPTR_RESTRICT_LEN 1
#define KPTR_RESTRICT_PATH "/proc/sys/kernel/kptr_restrict"

static void trim_module_name_suffix(char *pName);
static bool parse_module_name(char *line, char **module_name);
static bool _lookup_peer_modules(ProcessContext *context, struct list_head *output_modules);
static int get_kptr_restrict(void);
static void set_kptr_restrict(int new_kptr_restrict);

/*
 * NOTE: This will not currently work on RHEL 8, vfs_read()/vfs_write()
 * are visible in linux 2.x and 3.x (RHEL 6 and 7) but after
 * linux 4.14 vfs_read()/vfs_write() are no longer exported.
 * However they are replaced with kernel_read()/kernel_write() and we
 * can use those instead if we ever want to build for those kernels.
 */

/*
 * lookup_symbols
 * @struct symbols_s* p_symbols - a list of the functions to search for
 * Provides access to global symbols listed by the kernel via /proc/kallsyms by name.
 */
void lookup_symbols(ProcessContext *context, struct symbols_s *p_symbols)
{
    struct file *pFile  = NULL;
    char *buffer = NULL;
    int               ret    = 0;
    loff_t            offset = 0;
    mm_segment_t      oldfs = get_fs();
    unsigned int l_pfx = 0;  // length of *pSubStr memmove()d from end to beginning
    struct symbols_s *curr_symbol;
    unsigned int n_unk = 0;  // number of unknown symbols
    int current_kptr_restrict = get_kptr_restrict();

    TRY(p_symbols && p_symbols->name[0]);

    /*
     * Documentation/sysctl/kernel.txt:
     *  When kptr_restrict is set to (0), there are no restrictions.  When
     *  kptr_restrict is set to (1), the default, kernel pointers
     *  printed using the %pK format specifier will be replaced with 0's
     *  unless the user has CAP_SYSLOG.  When kptr_restrict is set to
     *  (2), kernel pointers printed using %pK will be replaced with 0's
     *  regardless of privileges.
     */
    if (current_kptr_restrict > 0)
    {
        set_kptr_restrict(0);
    }

    // Initialize all the addresses to 0 in case it is not found
    for (curr_symbol = p_symbols; curr_symbol->name[0]; ++curr_symbol) {
        *curr_symbol->addr = 0;
        ++n_unk;
    }

    // Open /proc/kallsyms
    set_fs(get_ds());
    pFile = filp_open("/proc/kallsyms", O_RDONLY, 0);
    TRY(!IS_ERR(pFile));

    // Allocate a buffer to read data into
    PUSH_GFP_MODE(context, GFP_MODE(context) | __GFP_ZERO);
    buffer = (char *)cb_mem_cache_alloc_generic(CB_KALLSYMS_BUFFER*sizeof(unsigned char), context);
    POP_GFP_MODE(context);
    TRY_STEP_MSG(CLOSE_EXIT, buffer, DL_ERROR, "Out of memory.");

    // Read the file until the end or all symbols found.
    while (0 < (ret = vfs_read(pFile, &buffer[l_pfx], CB_KALLSYMS_BUFFER-1 - l_pfx, &offset)))
    {
        char *pBuffer = buffer;  // strsep() pointer

        // Make sure the buffer is NULL terminated
        buffer[l_pfx + ret] = '\0';
        l_pfx = 0;  // no prefix yet

        // We will tokenize the data by '\n' using strsep.  This will eventually consume the
        //  contents of pBuffer until it is NULL.  At that point we will read in more data from
        //  /proc/kallsyms
        while (pBuffer != NULL) {
            // Grab the next token ending with '\n'  (The last line in the file does have '\n'.)
            char *pSubStr = strsep(&pBuffer, "\n");

            if (pSubStr == NULL) {
                // pSubStr is NULL so bail.  This should never happen
                continue;
            }
            // If pBuffer is NULL, we assume that we do not have a full token.
            //  Move *pSubStr back to the beginning of buffer, and remember its length
            //  so that we can concatentate a vfs_read().  [The alternate method
            //  of decrementing 'offset' then re-reading the bytes now in *pSubStr
            //  into &buffer[0] is expensive because seq_file implements backwards
            //  lseek() by re-setting the file position to 0, then moving forward
            //  to the desired offset.]
            // Then exit this inner loop.
            if (pBuffer == NULL) {
                memmove(&buffer[0], pSubStr, l_pfx = strlen(pSubStr));
                break;
            }

            // We will now further tokenize the data to get the address and symbol name
            {
                int len = 0;
                char *pAddr = strsep(&pSubStr, " ");
                char *pJunk = strsep(&pSubStr, " "); // symbol classification
                char *pName = strsep(&pSubStr, " ");
                (void)pJunk;
                if (NULL == pAddr || NULL == pName) {
                    // pAddr and pName is NULL so bail on this iteration.  This should never happen
                    continue;
                }

                // Use as pre-check to avoid useless calls to strcmp.
                // memcmp(dst, src, 1+ strlen(src)) would be nice instead of strcmp();
                // but memcmp does not stop at the first '\0' in dst, so might SIGSEGV.

                // The lines that have symbols exported by event_collectors have a suffix,
                // that the following function will drop.
                // e.g.
                // ffffffffa0335040 r __kcrctab_event_collector_1_6_12350_disable	[event_collector_1_6_12350]
                //

                trim_module_name_suffix(pName);

                len = strlen(pName);

                // Loop over all of the symbols we are looking for.
                // Skip those already found; the list is short.
                for (curr_symbol = p_symbols; curr_symbol->name[0]; ++curr_symbol) {

                    if (!*curr_symbol->addr  // not yet found
                    &&  len == curr_symbol->len  // length matches
                    &&  0 == strcmp(pName, curr_symbol->name)  // full string matches
                    ) {
                        unsigned long addr = 0;
                        #if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
                            #define kstrtoul strict_strtoul
                        #endif
                        ret = kstrtoul(pAddr, 16, &addr);
                        if (ret != 0) {
                            TRACE(DL_ERROR, "Failed to convert address string for %s. Error %d", pName, ret);
                        } else {
                            TRACE(DL_INFO, "Discovered address of %s (0x%lx)", pName, addr);
                            *curr_symbol->addr = addr;
                            TRY_STEP(CLOSE_EXIT, --n_unk);
                        }
                        break;
                    }
                } // for curr_symbol
            } // block
        } // while pBuffer
    } // while not EOF

CATCH_CLOSE_EXIT:
    if (buffer != NULL) {
        cb_mem_cache_free_generic(buffer);
        buffer = NULL;
    }
    if (pFile != NULL) {
        filp_close(pFile, NULL);
        pFile = NULL;
    }
CATCH_DEFAULT:
    if (current_kptr_restrict > 0)
    {
        set_kptr_restrict(current_kptr_restrict);
    }
    set_fs(oldfs);
}

static void trim_module_name_suffix(char *pName)
{
    char *substrStart = strstr(pName, "["CB_APP_PROC_DIR);

    if (substrStart)
    {
        *substrStart = 0;
        substrStart--;
        // Trim the trailing spaces.
        while (*substrStart == ' ' || *substrStart == '\t')
        {
            *substrStart = 0;
            substrStart--;
        }
    }
}

/**
 * Looks up other event_collectors loaded in the kernel.
 * For each event_collector found, the routine will
 * - Construct a PEER_MODULE struct and add it the output list.
 * - Also the routine will attempt to lookup the functions the peer exports
 *   to manage the state of the peer module and sets these up in PEER_MODULE struct also.
 *
 * For backwards compatibility the routine does not fail if it cannot resolve an expected function,
 * in this case it will just set the corresponding field in PEER_MODULE to null.
 *
 *
 * @param peer_modules
 * @return
 */
bool lookup_peer_module_symbols(ProcessContext *context, struct list_head *peer_modules)
{
    bool result = true;
    PEER_MODULE *elem = NULL;
    int peer_module_count = 0;
    int i = 0;
    struct symbols_s *symbols = NULL;

    if (!_lookup_peer_modules(context, peer_modules))
    {
        TRACE(DL_ERROR, "Failed to lookup peer modules");
        result = false;
        goto Exit;
    }

    /**
     * Populate the names for the functions for each peer module.
     *
     * Each module will export a unique name for the functions.
     * e.g. The module with name event_collector_12349 will export a name.
     * event_collector_12349_disable_if_not_connected
     *
     */
    list_for_each_entry(elem, peer_modules, list)
    {
        int remaining_char_count = sizeof(elem->disable_fn_name) - 1;

        elem->disable_fn_name[0] = 0;

        strncat(elem->disable_fn_name, elem->module_name, remaining_char_count);
        remaining_char_count -= strnlen(elem->module_name, remaining_char_count);

        strncat(elem->disable_fn_name, disable_suffix, remaining_char_count);
        remaining_char_count -= sizeof(disable_suffix);

        peer_module_count += 1;
    }

    PUSH_GFP_MODE(context, GFP_MODE(context) | __GFP_ZERO);
    symbols = cb_mem_cache_alloc_generic(sizeof(struct symbols_s) * (peer_module_count + 1), context);
    POP_GFP_MODE(context);

    i = 0;
    list_for_each_entry(elem, peer_modules, list)
    {
        strncat(symbols[i].name, elem->disable_fn_name, sizeof(symbols[i].name) - 1);
        symbols[i].len = (char) strlen(symbols[i].name);
        symbols[i].addr = (unsigned long *) &elem->disable_fn;
        i++;

    }

    lookup_symbols(context, symbols);

    if (verify_symbols(context, symbols) < 0)
    {
        TRACE(DL_ERROR, "%s Failed to lookup symbols for some peer modules", __func__);
    }

Exit:
    if (symbols != NULL)
    {
        cb_mem_cache_free_generic(symbols);
    }

    return result;
}

static bool _lookup_peer_modules(ProcessContext *context, struct list_head *output_modules)
{
    struct file *pFile  = NULL;
    bool           result = true;
    loff_t         offset = 0;
    int            ret    = 0;
    int            l_pfx  = 0;
    char          *buffer = NULL;

    INIT_LIST_HEAD(output_modules);

    set_fs(get_ds());
    pFile = filp_open("/proc/modules", O_RDONLY, 0);
    if (IS_ERR(pFile))
    {
        TRACE(DL_ERROR, "%s /proc/modules open failed", __func__);
        result = false;
        goto Exit;
    }

    PUSH_GFP_MODE(context, GFP_MODE(context) | __GFP_ZERO);
    buffer = (char *)cb_mem_cache_alloc_generic(CB_KALLSYMS_BUFFER*sizeof(unsigned char), context);
    POP_GFP_MODE(context);
    if (buffer == NULL)
    {
        TRACE(DL_ERROR, "%s Out of memory", __func__);
        result = false;
        goto Exit;
    }

    while (true)
    {
        char *line_start = buffer;

        ret = vfs_read(pFile, &buffer[l_pfx], CB_KALLSYMS_BUFFER - 1 - l_pfx, &offset);

        if (ret <= 0)
        {
            goto Exit;
        }

        // Read ret bytes, total string to process is left over prefix + number of bytes read.
        line_start[l_pfx + ret] = 0;

        while (line_start != NULL)
        {
            char *line = strsep(&line_start, "\n");

            if (line_start == NULL)
            {
                /**
                 * Did not find line ending.
                 * Store the read bytes so the subsequent read can append the read result
                 * to the bytes read.
                 */
                l_pfx = strlen(line);
                memmove(&buffer[0], line, l_pfx);
                break;
            } else
            {
                char *module_name = NULL;
                /**
                 * Found a line ending.
                 * Now process the line.
                 */
                parse_module_name(line, &module_name);

                if (strstr(module_name, CB_APP_NAME) && strcmp(module_name, CB_APP_MODULE_NAME) != 0)
                {
                    /**
                     *  Found another module add it to the output list.
                     *  The strcmp in the if condition will make sure
                     *  that this module does not add an entry for itself.
                     */
                    PEER_MODULE *temp = (PEER_MODULE *) cb_mem_cache_alloc_generic(sizeof(PEER_MODULE), context);

                    temp->module_name[0] = 0;
                    strncat(temp->module_name, module_name, sizeof(temp->module_name) - 1);

                    list_add(&(temp->list), output_modules);
                }
            }
        }
    }

Exit:
    if (buffer != NULL)
    {
        cb_mem_cache_free_generic(buffer);
        buffer = NULL;
    }
    if (pFile != NULL)
    {
        filp_close(pFile, NULL);
        pFile = NULL;
    }
    if (result != true)
    {
        free_peer_module_symbols(output_modules);

        INIT_LIST_HEAD(output_modules);
    }

    return result;
}

void free_peer_module_symbols(struct list_head *peer_modules)
{
    struct PEER_MODULE *elem, *next;

    list_for_each_entry_safe(elem, next, peer_modules, list)
    {
        list_del_init(&elem->list);
        cb_mem_cache_free_generic(elem);
        elem = NULL;
    }
}

/**
 * Gets the module name from the line.
 * e.g.
 * Input: ablk_helper 13597 1 aesni_intel, Live 0xffffffffa0233000
 * Output: ablk_helper
 *
 * @param line
 * @param module_name
 * @return
 */
static bool parse_module_name(char *line, char **module_name)
{
    *module_name = strsep(&line, " ");
    return true;
}

int verify_symbols(ProcessContext *context, struct symbols_s *p_symbols)
{
    struct symbols_s *curr_symbol;
    int ret = 0;

    for (curr_symbol = p_symbols; curr_symbol->name[0]; ++curr_symbol)
    {
            if (!(*curr_symbol->addr))
            {
                TRACE(DL_INIT, "cb_findsyms_init: no address for %s", curr_symbol->name);

                ret = -1;
            }
    }

    return ret;
}

/**
 * Gets the kptr_restrict setting.
 *
 * @return kptr_restrict setting or -1 if unable to retrieve
 */
static int get_kptr_restrict(void)
{
    struct file *pFile = NULL;
    ssize_t      ret;
    char         buffer[KPTR_RESTRICT_LEN + 1];
    int          current_kptr_restrict = -1;
    loff_t       offset                = 0;
    mm_segment_t oldfs                 = get_fs();

    set_fs(get_ds());
    pFile = filp_open(KPTR_RESTRICT_PATH, O_RDONLY, 0);
    TRY(!IS_ERR(pFile));

    ret = vfs_read(pFile, buffer, KPTR_RESTRICT_LEN, &offset);
    if (ret != KPTR_RESTRICT_LEN)
    {
        TRACE(DL_ERROR, "kptr_restrict: read failed, %zd", ret);
        goto CATCH_DEFAULT;
    }

    buffer[KPTR_RESTRICT_LEN] = 0;
    if (0 != kstrtoint(buffer, 0, &current_kptr_restrict))
    {
        TRACE(DL_ERROR, "kptr_restrict: failed to convert to int %s", buffer);
        goto CATCH_DEFAULT;
    }

CATCH_DEFAULT:
    if (pFile != NULL) {
        filp_close(pFile, NULL);
        pFile = NULL;
    }
    set_fs(oldfs);
    return current_kptr_restrict;
}

/**
 * Sets the kptr_restrict setting.
 *
 * @param new_kptr_restrict
 */
static void set_kptr_restrict(int new_kptr_restrict)
{
    struct file *pFile = NULL;
    char         buffer[KPTR_RESTRICT_LEN + 1];
    ssize_t      ret;
    loff_t       offset = 0;
    mm_segment_t oldfs  = get_fs();

    set_fs(get_ds());
    pFile = filp_open(KPTR_RESTRICT_PATH, O_WRONLY, 0);
    TRY(!IS_ERR(pFile));

    if (KPTR_RESTRICT_LEN != snprintf(buffer, sizeof(buffer), "%d", new_kptr_restrict))
    {
        TRACE(DL_ERROR, "kptr_restrict: failed to convert to string %d", new_kptr_restrict);
        goto CATCH_DEFAULT;
    }

    ret = vfs_write(pFile, buffer, KPTR_RESTRICT_LEN, &offset);
    if (ret != KPTR_RESTRICT_LEN)
    {
        TRACE(DL_ERROR, "kptr_restrict: write failed %zd", ret);
        goto CATCH_DEFAULT;
    }

CATCH_DEFAULT:
    if (pFile != NULL) {
        filp_close(pFile, NULL);
        pFile = NULL;
    }
    set_fs(oldfs);
}

int cb_findsyms_init(ProcessContext *context, struct symbols_s *p_symbols)
{
        lookup_symbols(context, p_symbols);
        if (verify_symbols(context, p_symbols) < 0) {
                TRACE(DL_INIT, "%s failed", __func__);
                return -ENOTSUPP;
        }
        return 0;
}
