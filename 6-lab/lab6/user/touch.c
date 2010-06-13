#include <inc/lib.h>

void usage() {
	cprintf("Usage:\n\ttouch file1 [file*]\n");
}

void umain(int argc, char **argv) {
	if (argc < 2) {
		usage();
		return;
	}
	int i, r;
	for (i = 1; i < argc; i++) {
		r = open(argv[i], O_CREAT);
		if (r < 0) {
			if (r == -E_BAD_PATH)
				cprintf("touch: path %s not exists\n", argv[i]);
			else 
				panic("touch error at path %s: %e\n", argv[i], r);
		}
	}
}
