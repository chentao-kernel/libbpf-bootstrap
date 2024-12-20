# Makefile for building libnet.so

CC = gcc
AR = ar
SOURCE = ../.output
INCLUDE = $(SOURCE)
CFLAGS = -Wall -fPIC -I.  # 添加 -fPIC 以生成位置无关代码，支持动态库
LDFLAGS = -shared          # 指定生成动态库
LIBBPF = $(SOURCE)/libbpf.a          # 静态库文件
LIBELF = libelf_pic.a
TARGET = libebpf.so         # 目标动态库
SRCS = net.c               # 源文件
OBJS = $(SRCS:.c=.o)       # 将源文件编译成目标文件
LIBBPF_OBJS = $(shell ar t $(LIBBPF))
LIBELF_OBJS = $(shell ar t $(LIBELF))
LIBBPF_OBJS :=$(LIBBPF_OBJS:.o=.o)

# 默认目标
all: $(TARGET)

# 解压 libbpf.a
$(LIBBPF_OBJS): $(LIBBPF)
	cp $(LIBBPF) .
	$(AR) x libbpf.a
# 解压 libelf_pic.a
$(LIBELF_OBJS): $(LIBELF)
	$(AR) x $(LIBELF)

# 编译动态库
$(TARGET): $(LIBBPF_OBJS) $(LIBELF_OBJS) $(OBJS)
	@echo "work"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 

# 编译目标文件
%.o: %.c
	$(CC) $(CFLAGS) -I $(INCLUDE) -c $< -o $@

# 清理编译生成的文件
clean:
	rm -f $(OBJS) $(TARGET) *.o *.os

.PHONY: all clean
