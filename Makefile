# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++17 -I/opt/homebrew/opt/nlohmann-json/include -I/opt/homebrew/opt/openssl@3/include

# Linker flags
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/curl/lib -lcurl -lssl -lcrypto

# Target executable
TARGET = file_integrity_monitor

# Source files
SRCS = main.cpp malwarebazaar.cpp

# Object files in the build directory
OBJS = $(patsubst %.cpp,build/%.o,$(SRCS))

# Create build directory if it doesn't exist
$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

build/%.o: %.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -rf build $(TARGET)
