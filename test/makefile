# Try to detect the OS running, and adjust commands as needed.
ifeq ($(OS),Windows_NT)
	ifeq ($(shell uname -s),) # not in a bash-like shell
	CLEANUP = del /F /Q
	MKDIR = mkdir
	else # in a bash-like shell, like msys
	CLEANUP = rm -f
	MKDIR = mkdir -p
	endif
	TARGET_EXTENSION = .exe
else
	CLEANUP = rm -f
	MKDIR = mkdir -p
	TARGET_EXTENSION = .out
endif

C_COMPILER = gcc

UNITY_ROOT = ../unity
DUMBAES_ROOT = ..

CFLAGS = -std=c99
CFLAGS += -Wextra
CFLAGS += -Wpointer-arith
CFLAGS += -Wcast-align
CFLAGS += -Wwrite-strings
CFLAGS += -Wswitch-default
CFLAGS += -Wunreachable-code
CFLAGS += -Winit-self
CFLAGS += -Wmissing-field-initializers
CFLAGS += -Wno-unknown-pragmas
CFLAGS += -Wstrict-prototypes
CFLAGS += -Wundef
CFLAGS += -Wold-style-definition

INC_DIRS = -I$(UNITY_ROOT)/src -I$(DUMBAES_ROOT)/inc

TARGET_BASE1 = test1
TARGET1 = $(TARGET_BASE1)$(TARGET_EXTENSION)
SRC_FILES1 = $(UNITY_ROOT)/src/unity.c test_transformations.c $(DUMBAES_ROOT)/src/dumbAES_transformations.c $(DUMBAES_ROOT)/src/dumbAES_cipher.c  $(DUMBAES_ROOT)/src/dumbAES_internal.c $(DUMBAES_ROOT)/src/dumbAES_key_expansion.c  

TARGET_BASE2 = test2
TARGET2 = $(TARGET_BASE2)$(TARGET_EXTENSION)
SRC_FILES2 = $(UNITY_ROOT)/src/unity.c test_key_expansion.c $(DUMBAES_ROOT)/src/dumbAES_key_expansion.c $(DUMBAES_ROOT)/src/dumbAES_transformations.c 

TARGET_BASE3 = test3
TARGET3 = $(TARGET_BASE3)$(TARGET_EXTENSION)
SRC_FILES3 = $(UNITY_ROOT)/src/unity.c test_cipher.c $(DUMBAES_ROOT)/src/dumbAES_cipher.c $(DUMBAES_ROOT)/src/dumbAES_internal.c $(DUMBAES_ROOT)/src/dumbAES_key_expansion.c $(DUMBAES_ROOT)/src/dumbAES_transformations.c 

all: default

default: clean test_transformations test_key_expansion test_cipher

test_transformations: $(SRC_FILES1)
	$(C_COMPILER) $(CFLAGS) $(INC_DIRS) $(SRC_FILES1) -o $(TARGET1)
	- ./$(TARGET1)
	$(CLEANUP) $(TARGET1)

test_key_expansion: $(SRC_FILES2)
	$(C_COMPILER) $(CFLAGS) $(INC_DIRS) $(SRC_FILES2) -o $(TARGET2)
	- ./$(TARGET2)
	$(CLEANUP) $(TARGET2)

test_cipher: $(SRC_FILES2)
	$(C_COMPILER) $(CFLAGS) $(INC_DIRS) $(SRC_FILES3) -o $(TARGET3)
	- ./$(TARGET3)
	$(CLEANUP) $(TARGET3)

clean:
	$(CLEANUP) $(TARGET1)
	$(CLEANUP) $(TARGET2)
	$(CLEANUP) $(TARGET3)