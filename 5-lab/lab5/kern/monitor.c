// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/trap.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line

int mon_show_map(int argc, char **argv, struct Trapframe *tf);
int mon_set_perm(int argc, char **argv, struct Trapframe *tf);
int mon_dump_va(int argc, char **argv, struct Trapframe *tf);
int mon_dump_pa(int argc, char **argv, struct Trapframe *tf);
int mon_alloc_page(int argc, char **argv, struct Trapframe *tf);
int mon_free_page(int argc, char **argv, struct Trapframe *tf);
int mon_page_status(int argc, char **argv, struct Trapframe *tf);


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{"backtrace", "Trace the information of registers in function call", mon_backtrace} ,
	{"show_map", "Show mappings from virtual address to physical page",  mon_show_map }, 
	{"set_perm", "Set permission for pages", mon_set_perm },
	{"dump_va", "Dump value of vitual address", mon_dump_va },
	{"dump_pa", "Dump value of physical address", mon_dump_pa },
	{"alloc_page", "Allocate a page", mon_alloc_page },
	{"page_status", "Query page status", mon_page_status },
	{"free_page", "Free a page", mon_free_page }
};

#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start %08x (virt)  %08x (phys)\n", _start, _start - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-_start+1023)/1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	//code for printing registers ebp, eip and args
	/* lab1 backtrace
	cprintf("Stack backtrace:\n");
	uint32_t ebp = read_ebp();
	//format :
	//ebp f0109e58  eip f0100a62  args 00000001 f0109e80 f0109e98 f0100ed2 00000031
	while(ebp != 0){
		cprintf("ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n", 
		ebp, *(uint32_t *)(ebp + 4),
			 *(uint32_t *)(ebp + 8), 
			 *(uint32_t *)(ebp + 12), 
			 *(uint32_t *)(ebp + 16), 
			 *(uint32_t *)(ebp + 20), 
			 *(uint32_t *)(ebp + 24));
		ebp = *(uint32_t *) ebp;  // get caller
	}
	return 0;*/

	//lab 2 backtrace
	cprintf("Stack backtrace\n");
	uint32_t *ebp = (uint32_t *)read_ebp();
	uint32_t eip = read_eip();
	char function_name[50];
	int i;
	struct Eipdebuginfo info;
	while(ebp != NULL) {
		debuginfo_eip(eip, &info);
		strncpy(function_name, info.eip_fn_name, info.eip_fn_namelen);
		function_name[info.eip_fn_namelen] = '\0';
		cprintf("%s:%d: %s+%x\n",
			info.eip_file,
			info.eip_line,
			function_name,
			eip - info.eip_fn_addr);
		cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n",
			ebp, eip, ebp[2], ebp[3], ebp[4], ebp[5], ebp[6]);
		eip = ebp[1];
		ebp = (uint32_t *)(*ebp);
	}
	return 0;
}

//----------------------Chanllenge----------------

char char_map(uintptr_t i){
	if(i == 0) return '0';
	else return '1';
}

int
mon_show_map(int argc, char **argv, struct Trapframe *tf)
{
	if(argc != 3){
		cprintf("	Wrong arguments.\n	Formation \"showmappings begin_address end_address\" expected.\n");
		return 0;
	}
	uintptr_t begin_addr, end_addr, va;
	begin_addr = strtol(argv[1], NULL, 0);
	end_addr = strtol(argv[2], NULL, 0);
	//align addresses to page size
	if((begin_addr & (PGSIZE - 1)) != 0){
		begin_addr -= PGSIZE;
		begin_addr &= ~(PGSIZE - 1);
	}
	if((end_addr & (PGSIZE - 1)) != 0){
		end_addr += PGSIZE;
		end_addr &= ~(PGSIZE - 1);
	}
	cprintf("	vir_addr   phy_addr   P W U PWT PCD A D PS MBZ AVAIL\n"); 
	for(va = begin_addr; va <= end_addr; va += PGSIZE){
		pde_t pde = vpd[PDX(va)];
		if((pde & PTE_P) == 0){
			cprintf("	UNMAPPED ADDRESS 0x%08x.\n", (va & 0xFFFFF000));
			continue;
		}
		pte_t pte = vpt[PDX(va) * 1024 + PTX(va)];
		if((pte & PTE_P) == 0){
			cprintf("	UNMAPPED ADDRESS 0x%08x.\n", (va & 0xFFFFF000));
			continue;
		}
		cprintf("	0x%08x 0x%08x ", (va & 0xFFFFF000), PTE_ADDR(pte));
		cprintf("%c ", char_map(pte & PTE_P));
		cprintf("%c ", char_map(pte & PTE_W));
		cprintf("%c ", char_map(pte & PTE_U));
		cprintf("%c   ", char_map(pte & PTE_PWT));
		cprintf("%c   ", char_map(pte & PTE_PCD));
		cprintf("%c ", char_map(pte & PTE_A));
		cprintf("%c ", char_map(pte & PTE_D));
		cprintf("%c  ", char_map(pte & PTE_PS));
		cprintf("%02x  ", (pte & PTE_MBZ) >> 7);
		cprintf("%03x  \n", (pte & PTE_AVAIL) >> 9);
	}
	return 0;
}

int
mon_set_perm(int argc, char **argv, struct Trapframe *tf)
{
	if(argc != 4){
		cprintf("	Wrong arguments.\n	Formation \"showmappings begin_address end_address\" expected.\n");
		return 0;
	}
	uintptr_t begin_addr, end_addr, va, perm;
	begin_addr = strtol(argv[1], NULL, 0);
	end_addr = strtol(argv[2], NULL, 0);
	perm = strtol(argv[3], NULL, 0);
	if(perm != 0) perm = 1;
	//align addresses to page size
	if((begin_addr & (PGSIZE - 1)) != 0){
		begin_addr -= PGSIZE;
		begin_addr &= ~(PGSIZE - 1);
	}
	if((end_addr & (PGSIZE - 1)) != 0){
		end_addr += PGSIZE;
		end_addr &= ~(PGSIZE - 1);
	}
	for(va = begin_addr; va <= end_addr; va += PGSIZE){
		pde_t pde = vpd[PDX(va)];
		if((pde & PTE_P) == 0){
			cprintf("	UNMAPPED ADDRESS 0x%08x.\n", (va & 0xFFFFF000));
			continue;
		}
		pte_t *pte = (pte_t *)(&vpt[PDX(va) * 1024 + PTX(va)]);
		if(((*pte) & PTE_P) == 0){
			cprintf("	UNMAPPED ADDRESS 0x%08x.\n", (va & 0xFFFFF000));
			continue;
		}
		if(perm == 0){
			(*pte) &= 0xfffffffb;
		}
		else (*pte) |= 4;
	}
	return 0;
}

int mon_dump_va(int argc, char **argv, struct Trapframe *tf)
{
	if(argc != 3){
		cprintf("	Wrong arguments.\n	Formation \"showmappings begin_address end_address\" expected.\n");
		return 0;
	}
	uintptr_t begin_addr, end_addr, va;
	begin_addr = strtol(argv[1], NULL, 0);
	end_addr = strtol(argv[2], NULL, 0);
	for(va = begin_addr; va <= end_addr; va += 4){
		if(va >= KERNBASE && va <= 0xffffffff)
			cprintf("	va: 0x%08x	value: %08x\n", va, (*(uint32_t*)va));
	}
	return 0;
}

int mon_dump_pa(int argc, char **argv, struct Trapframe *tf)
{
	if(argc != 3){
		cprintf("	Wrong arguments.\n	Formation \"showmappings begin_address end_address\" expected.\n");
		return 0;
	}
	uintptr_t begin_addr, end_addr, pa;
	begin_addr = strtol(argv[1], NULL, 0);
	end_addr = strtol(argv[2], NULL, 0);
	for(pa = begin_addr; pa <= end_addr; pa += 4){
		if(pa >= 0 && pa <= 0xfffffff)
			cprintf("	pa: 0x%08x	value: %08x\n", pa + KERNBASE, (*(uint32_t*)(pa + KERNBASE)));
	}
	return 0;
}

int 
mon_alloc_page(int argc, char **argv, struct Trapframe *tf)
{
	if(argc != 1){
		cprintf("	Wrong arguments.\n	Formation \"alloc_page\" expected.\n");
		return 0;
	}
	struct Page *page;
	if(page_alloc(&page) != 0){
		cprintf("	Page allocate failed.\n");
		return 0;
	}
	page->pp_ref++;
	cprintf("	Page allocate successfully at 0x%x\n", page2pa(page));
	return 0;
}

int
mon_page_status(int argc, char **argv, struct Trapframe *tf)
{
	if(argc != 2){
		cprintf("	Wrong arguments.\n	Formation \"page_status address\" expected.\n");
		return 0;
	}
	struct Page* page;
	uintptr_t pa = strtol(argv[1], NULL, 0);
	page = pa2page(pa);
	if(page->pp_ref != 0)
		cprintf("	allocated\n");
	else
		cprintf("	free\n");
	return 0;
}

int
mon_free_page(int argc, char **argv, struct Trapframe *tf)
{
	if(argc != 2){
		cprintf("	Wrong arguments.\n	Formation \"free_page address\" expected.\n");
		return 0;
	}
	struct Page* page;
	uintptr_t pa = strtol(argv[1], NULL, 0);
	page = pa2page(pa);
	page_decref(page);
	return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
