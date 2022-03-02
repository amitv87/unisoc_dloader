TARGET := dloader

MKDIR_P = mkdir -p
BUILD_DIR := $(if $(BUILD_DIR),$(BUILD_DIR),.build)

INC_FLAGS := -MMD -MP

rwildcard = $(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))
SRCS := $(call rwildcard,,*.c)

OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

$(BUILD_DIR)/$(TARGET): $(OBJS)
	@echo "\033[92;1mLinking CXX executable $@\033[0m"
	$(CC) $(LD_FLAGS) -o $@ $(OBJS) $(APP_LIBS) ${STD_LIBS}
	@echo Built target $@

$(BUILD_DIR)/%.c.o: %.c
	@echo "\033[92mBuilding C object $<\033[0m"
	$(MKDIR_P) $(dir $@)
	$(CC) $(INC_FLAGS) $(DEFINES) $(COMPILE_FLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.cpp.o: %.cpp
	@echo "\033[92mBuilding CXX object $<\033[0m"
	$(MKDIR_P) $(dir $@)
	$(CXX) $(INC_FLAGS) $(DEFINES) $(COMPILE_FLAGS) $(CXXFLAGS) -c $< -o $@

.PHONY: clean

clean:
	$(RM) -rf $(BUILD_DIR)
	$(MKDIR_P) $(BUILD_DIR)
	@touch $(BUILD_DIR)/mmarker
	@echo "\033[92mCleaned build dir...\033[0m"

all: $(BUILD_DIR)/$(TARGET)

size: $(BUILD_DIR)/$(TARGET)
	$(SIZE) $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/mmarker: Makefile
	$(RM) -r $(BUILD_DIR)/*
	$(MKDIR_P) $(dir $@)
	@touch $@
	@echo "\033[92mMakefile changed, rebuilding...\033[0m"

-include $(BUILD_DIR)/mmarker $(DEPS)
