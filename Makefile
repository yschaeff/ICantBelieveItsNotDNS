CC=/home/yuri/repo/webrepl/webrepl_cli.py
DST=10.0.0.138
SOURCES=main.py boot.py trusted_networks.py net_utils.py
OBJECTS=$(SOURCES:.py=.o)

.NOTPARALLEL: %.o list wipe
#.PHONY: list wipe clean

all: $(OBJECTS)
%.o: %.py
	cat $< | python3 scrub.py > _tmp
	$(CC) _tmp $(DST):/$<
	rm _tmp
	touch $@
