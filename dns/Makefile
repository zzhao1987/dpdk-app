
ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = nis-dns

# all source are stored in SRCS-y
SRCS-y += dns.c
SRCS-y += main.c

CFLAGS += $(WERROR_FLAGS)

# 使用make DEBUG=y 来编译debug和profile版本
ifdef DEBUG
	CFLAGS +=-DNIS_DEBUG
	CFLAGS += -g
	CFLAGS += -O0
else
	CFLAGS +=-O3
endif

include $(RTE_SDK)/mk/rte.app.mk
