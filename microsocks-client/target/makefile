#指定编译器
CC = gcc

#指定额外的参数
#如果是正式版软件，删除-ggdb或-g参数
FLAGS = -Wall -Werror -g

#生成文件名和生成所需要的文件
app: main.c error_functions.c
	${CC} -o $@ $^ ${FLAGS}

#如果生成的文件名修改了，下面的文件名也需要修改
clean:
	rm -f app *.lo *.o

.PHONY: app clean

