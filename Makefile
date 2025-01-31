GNUMAKEFLAGS := -r
# Flags needed for correctness
MANDATORY_CFLAGS := -fno-strict-aliasing -Werror=format \
						  -Werror=implicit-function-declaration \
						  -Werror=missing-prototypes \
						  -pedantic-errors
TARGET = '$(subst ','\'',$@)'#
SOURCE = '$(subst ','\'',$<)'#
# marmarek: detect based on $(CC) ?
ifeq "$(WARNINGS)" "clang"
EXTRA_CFLAGS := -fsanitize=undefined -fsanitize-minimal-runtime  \
	-fPIC -Weverything -Wno-c++98-compat \
	-Wno-gnu-zero-variadic-macro-arguments -Wno-disabled-macro-expansion -Wno-cast-align \
	-Wno-declaration-after-statement -Wno-unsafe-buffer-usage \
	-Wno-language-extension-token -O2
else ifeq "$(WARNINGS)" "gcc"
EXTRA_CFLAGS := -Winline -Wall -Wextra -fPIC
else ifeq "$(WARNINGS)" ""
EXTRA_CFLAGS :=
else
$(error Unknown value for $$(WARNINGS))
endif
LINK = $(CC) -Wl,-z,relro,-z,now $(EXTRA_CFLAGS) $(CFLAGS) $(MANDATORY_CFLAGS) -Wall -Wextra -o $(TARGET) $^
%.o: %.c Makefile
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) $(MANDATORY_CFLAGS) -Wall -Wextra -MD -MP -MF $(TARGET).dep -c -o $(TARGET) $(SOURCE)
all: winpe
check: test-winpe
	./test-winpe
winpe: winpe.o main.o
	$(LINK)
test-winpe: winpe.o test.o
	$(LINK)
clean:
	rm -f winpe test-winpe ./*.o ./*.dep
.PHONY: all check clean
	$(error do not try to make .PHONY)
-include ./*.dep
