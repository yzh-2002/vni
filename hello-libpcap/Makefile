CC = gcc
TARGET = hello
SRC = get-packets.c

# 需要链接的库
LIBS = -lpcap
# 默认目标
all: $(TARGET)

# 目标规则
$(TARGET): $(SRC)
	$(CC) -o $(TARGET) $(SRC) $(LIBS)

# 清理编译生成的文件
clean:
	rm -f $(TARGET)
