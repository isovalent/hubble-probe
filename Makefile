GO := go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin

all: hubble-probe

hubble-probe:
	$(GO) build ./cmd/hubble-probe/

clean:
	rm -f $(TARGET)

.PHONY: all clean hubble-fgs
