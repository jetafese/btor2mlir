# Compiler and flags
CXX = /opt/homebrew/Cellar/llvm@14/14.0.6/bin/clang++
LLVM_LINK = /opt/homebrew/Cellar/llvm@14/14.0.6/bin/llvm-link
CXXFLAGS = -emit-llvm -S
FUZZ_FLAGS = -fsanitize=fuzzer,address -g -O1

# Source and object files
SRC = test.cpp fuzz_helpers.cpp 
LLFILES = test.ll fuzz_helpers.ll 
LINKED_LL = final_linked_file.ll
EXECUTABLE = fuzz_executable

# Default target
all: $(EXECUTABLE)

# Compile the source files to LLVM IR (.ll)
%.ll: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

# Link the .ll files into a final linked LLVM IR file
$(LINKED_LL): $(LLFILES)
	$(LLVM_LINK) $^ -S -o $@

# Compile the linked LLVM IR to an executable with fuzzing enabled
$(EXECUTABLE): $(LINKED_LL)
	$(CXX) $(LINKED_LL) $(FUZZ_FLAGS) -o $@

# Run the executable
run: $(EXECUTABLE)
	./$(EXECUTABLE)

# Clean up generated files
clean:
	rm -f $(LLFILES) $(LINKED_LL) $(EXECUTABLE)

.PHONY: all clean run
