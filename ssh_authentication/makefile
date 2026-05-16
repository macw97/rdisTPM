.PHONY: build install clean

CFLAGS = -Wall -Wextra -O2
LIBS = $(shell pkg-config --cflags --libs tss2-esys) -ltss2-tctildr -ltss2-sys -ltss2-mu
TARGET = tpm_auth
SRC = src/tpm_auth.c

build: $(TARGET)

$(TARGET): $(SRC)
	gcc $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

install: $(TARGET)
	sudo install -m 755 -o root -g root $(TARGET) /usr/local/bin/tpm_auth
	chmod +x tpm_shell.sh
	sudo install -m 755 tpm_shell.sh /usr/local/bin/tpm_shell

clean:
	rm -f $(TARGET)