
KVER = $(shell uname -r)
DIR  = $(shell pwd) 

obj-m := odptest.o

all:
	make -C /lib/modules/$(KVER)/build M=$(DIR) modules

install: all
	true
