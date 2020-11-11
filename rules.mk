.PHONY: all

all: $(EXEC)

$(OBJS): $(BUILDDIR)/%.o : %.c Makefile rules.mk
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $(@) $(<)

$(DEPS): $(DEPSDIR)/%.d : %.c Makefile rules.mk
	@mkdir -p $(@D)
	-$(CC) $(CFLAGS) -MM -MP -MG -MT "$(@) $(<:%.c=$(BUILDDIR)/%.o)" $(<) > $(@)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -o $(@) $(^)

$(GENHBIN): %: %.c
	$(CC) $(CFLAGS) -o $(@) $(<)

$(GENH): %.h: % $(GENHBIN)
	./$(GENHBIN) $(<) > $(@)

include $(DEPS)


