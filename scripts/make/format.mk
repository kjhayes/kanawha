
# I generally don't like forcing formatting, but something
# keeps messing with my spacing/indentation and I'd like to
# be able to drop the heavy hammer and force all of my C
# code to use spaces instead of tabs...

format: FORCE
	find $(ROOT_DIR) -name "*.[ch]" | xargs clang-format -i

