CC := gcc
DEPS_DIRS_SCRIPT_PATH := ./scripts/get_deps_dirs.sh
DEPS_LIBS_SCRIPT_PATH := ./scripts/get_deps_libs.sh
GCC_DEPS_INCLUDE_FLAGS := $(shell $(DEPS_DIRS_SCRIPT_PATH))
GCC_DEPS_LIBS_FLAGS := $(shell $(DEPS_LIBS_SCRIPT_PATH))
CFLAGS := -Wall -O2
SRC_DIR := ./src
BUILD_DIR := ./build
TARGET_DYNAMIC := analyzer-dynamic
TARGET_STATIC := analyzer-static
SRCS := $(shell find $(SRC_DIRS) -name '*.c')
SRC_WITHOUT_PARENT_DIR = $(patsubst $(SRC_DIR)/%.c, ./%.c, $(SRCS))
OBJS := $(patsubst %.c, $(BUILD_DIR)/%.o, $(SRC_WITHOUT_PARENT_DIR))
DEPS = $(wildcard $(SRC_DIR)/*.h)

dynamic: $(TARGET_DYNAMIC)

static: $(TARGET_STATIC)

$(TARGET_DYNAMIC): $(OBJS)
	$(CC) $(GCC_DEPS_LIBS_FLAGS) $(CFLAGS) $^ -o $(BUILD_DIR)/$@

$(TARGET_STATIC): $(OBJS)
	$(CC) $(CFLAGS) $^ -Wl,-Bstatic -o $(BUILD_DIR)/$@ $(GCC_DEPS_LIBS_FLAGS) -Wl,-Bdynamic

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ $(GCC_DEPS_INCLUDE_FLAGS)


$(OBJS): $(DEPS)

clean:
	rm -rf $(BUILD_DIR)/*

.PHONY: dynamic static clean