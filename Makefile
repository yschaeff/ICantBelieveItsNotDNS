CC=/home/yuri/repo/webrepl/webrepl_cli.py
DST=10.0.0.138
SOURCES=main.py boot.py
OBJECTS=$(SOURCES:.py=.o)

.NOTPARALLEL: %.o list wipe
#.PHONY: list wipe clean

all: $(OBJECTS)
%.o: %.py
	$(CC) $< $(DST):/
	touch $@
