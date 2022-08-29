
doseccomp.elf: main.c seccomp-bpf.h
	gcc -o dosecomp.elf main.c

clean:
	rm -f doseccomp.elf
