# Compiler and flags
CXX = g++
CFLAGS = -Os -s -o POP42Patcher.exe -lcomdlg32 -lgdi32 -mwindows -static

# Targets
TARGET = POP42Patcher.exe
SRC = POP42Patcher.c
OBJ = main.o

# Default target
all: $(TARGET)

# Compile
main.o: $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Link everything
$(TARGET): $(OBJ)
	$(CXX) $(OBJ) \
	-lcomdlg32 -lgdi32 -mwindows -static -s \
	-o $(TARGET)

# Clean
clean:
	rm -f $(OBJ) $(TARGET)

