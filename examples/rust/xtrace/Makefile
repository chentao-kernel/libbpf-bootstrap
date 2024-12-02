# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
.ONESHELL:
SHELL = /bin/bash

CLANG_FMT=clang-format-12

C_FILES_TO_BE_CHECKED = $(shell find ./src -regextype posix-extended -regex '.*\.(h|c)' ! -regex '.*(headers|output)\/.*' | xargs)

fmt-check:
	@errors=0
	echo "Checking C and eBPF files and headers formatting..."
	$(CLANG_FMT) --dry-run -i $(C_FILES_TO_BE_CHECKED) > /tmp/check-c-fmt 2>&1
	clangfmtamount=$$(cat /tmp/check-c-fmt | wc -l)
	if [[ $$clangfmtamount -ne 0 ]]; then
		head -n30 /tmp/check-c-fmt
		errors=1
	fi
	rm -f /tmp/check-c-fmt
#
	if [[ $$errors -ne 0 ]]; then
		echo
		echo "Please fix formatting errors above!"
		echo "Use: $(MAKE) fmt-fix target".
		echo
		exit 1
	fi

# fmt-fix

fmt-fix:
	@echo "Fixing C and eBPF files and headers formatting..."
	$(CLANG_FMT) -i --verbose $(C_FILES_TO_BE_CHECKED)

