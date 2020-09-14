#
# Common list of .c-files and objects for all Makefiles.
# Keep the syntax here non-GNU to suite all make programs.
#
# 'O' (the .obj-suffix) and 'OBJ_DIR' must be defined prior to
# including this file from respective makefile.
#
WSOCK_SRC = common.c     \
            cpu.c        \
            firewall.c   \
            dnsbl.c      \
            dump.c       \
            hosts.c      \
            geoip.c      \
            geoip-gen4.c \
            geoip-gen6.c \
            idna.c       \
            inet_util.c  \
            init.c       \
            in_addr.c    \
            ip2loc.c     \
            overlap.c    \
            smartlist.c  \
            stkwalk.c    \
            vm_dump.c    \
            wsock_trace.c

ifeq ($(USE_LUA),1)
  WSOCK_SRC += wsock_trace_lua.c \
             # miniz.c
endif

COMMON_OBJ = $(OBJ_DIR)/common.$(O)    \
             $(OBJ_DIR)/cpu.$(O)       \
             $(OBJ_DIR)/dnsbl.$(O)     \
             $(OBJ_DIR)/idna.$(O)      \
             $(OBJ_DIR)/inet_util.$(O) \
             $(OBJ_DIR)/init_1.$(O)    \
             $(OBJ_DIR)/in_addr.$(O)   \
             $(OBJ_DIR)/getopt.$(O)    \
             $(OBJ_DIR)/smartlist.$(O) \
             $(OBJ_DIR)/vm_dump.$(O)

GEOIP_OBJ = $(COMMON_OBJ)            \
            $(OBJ_DIR)/geoip_1.$(O)  \
            $(OBJ_DIR)/ip2loc_1.$(O) \
            $(OBJ_DIR)/geoip-null.$(O)

BT_TEST_OBJ = $(OBJ_DIR)/bt_test.$(O)    \
              $(OBJ_DIR)/common.$(O)     \
              $(OBJ_DIR)/cpu.$(O)        \
              $(OBJ_DIR)/getopt.$(O)     \
              $(OBJ_DIR)/geoip.$(O)      \
              $(OBJ_DIR)/geoip-gen4.$(O) \
              $(OBJ_DIR)/geoip-gen6.$(O) \
              $(OBJ_DIR)/idna.$(O)       \
              $(OBJ_DIR)/inet_util.$(O)  \
              $(OBJ_DIR)/init_2.$(O)     \
              $(OBJ_DIR)/in_addr.$(O)    \
              $(OBJ_DIR)/smartlist.$(O)  \
              $(OBJ_DIR)/stkwalk.$(O)    \
              $(OBJ_DIR)/vm_dump.$(O)

ifeq ($(USE_LUA),1)
 # BT_TEST_OBJ += $(OBJ_DIR)/wsock_trace_lua.$(O)
endif

FIREWALL_TEST_OBJ = $(OBJ_DIR)/common.$(O)     \
                    $(OBJ_DIR)/cpu.$(O)        \
                    $(OBJ_DIR)/dnsbl.$(O)      \
                    $(OBJ_DIR)/firewall_1.$(O) \
                    $(OBJ_DIR)/geoip.$(O)      \
                    $(OBJ_DIR)/geoip-gen4.$(O) \
                    $(OBJ_DIR)/geoip-gen6.$(O) \
                    $(OBJ_DIR)/getopt.$(O)     \
                    $(OBJ_DIR)/idna.$(O)       \
                    $(OBJ_DIR)/in_addr.$(O)    \
                    $(OBJ_DIR)/inet_util.$(O)  \
                    $(OBJ_DIR)/init_3.$(O)     \
                    $(OBJ_DIR)/ip2loc.$(O)     \
                    $(OBJ_DIR)/overlap.$(O)    \
                    $(OBJ_DIR)/smartlist.$(O)  \
                    $(OBJ_DIR)/stkwalk.$(O)

MSVC_WSOCK_OBJ = $(OBJ_DIR)/$(WSOCK_SRC:.c=.$(O) $(OBJ_DIR)/)


