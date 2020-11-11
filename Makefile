# Config
VERSION := 1.0

CC ?= gcc
CFLAGS ?= -Wall -Wextra -O3 -std=c99 -ggdb

# Computed
PROJDIR := $(shell basename $(shell pwd))
DIST := $(PROJDIR)-$(VERSION).tar.gz

# Build directories
BUILDDIR := build
DEPSDIR := build

# Targets
OBJPATHS := pipe.o mem.o map.o token.o \
	dso.o prog.o trace.o meta.o \
	dump.o serialize.o files.o output.o main.o
EXEC := hperf

GENHBIN := genh
GENH := gen_dark.css.h gen_light.css.h gen_app.js.h

OBJS := $(OBJPATHS:%.o=$(BUILDDIR)/%.o)
DEPS := $(OBJS:$(BUILDDIR)/%.o=$(DEPSDIR)/%.d)
DOC_C := $(DOC_MAN:%=%.i)

# Export
export

# Rules
.PHONY: all clean force

all $(OBJS) $(EXEC): force
	$(MAKE) -f rules.mk $(@)

clean:
	rm -f $(EXEC) $(GENHBIN)
	rm -f $(GENH)
	rm -f $(shell find $(DEPSDIR) -name '*.d')
	rm -f $(shell find $(BUILDDIR) -name '*.o')

dist:
	cd ..; tar \
		--exclude-vcs \
		--exclude-vcs-ignores \
		-czf $(DIST) $(PROJDIR)

force:

