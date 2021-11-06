// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display a listing of function call frames", mon_backtrace},
	{ "showmappings", "Display all of the physical page mappings", mon_showmappings},
	{ "setperm", "Explicitly set, clear, or change the permissions of any mapping in the current address space", mon_setperm},
	{ "dump", "Dump the contents of a range of memory", mon_dump},
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	cprintf("Stack backtrace:\n");
	uint32_t ebp, eip, esp;
	uint32_t arg[5];
	ebp = read_ebp();
	while(ebp) // When to stop? See entry.S line 74.
	{
		esp = ebp + 4;
		eip = *((uint32_t *)esp);
		for(int i=0; i<5; i++)
		{
			esp += 4;
			arg[i] = *((uint32_t *)esp);
		}
		cprintf("  ebp %08x  eip %08x args %08x %08x %08x %08x %08x\n", ebp, eip,
		arg[0], arg[1], arg[2], arg[3], arg[4]);

		struct Eipdebuginfo info;
		debuginfo_eip(eip, &info);
		cprintf("         %s:%d: %.*s+%d\n", info.eip_file, info.eip_line, info.eip_fn_namelen, 
		info.eip_fn_name, eip-info.eip_fn_addr);

		ebp = *((uint32_t *)ebp);
	}
	return 0;
}


int mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 3)	// guiding information
	{
		cprintf("Type \"showmappings saddr eaddr\" to display mapping and permission\n");
		return 0;
	}
	uint32_t saddr = (uint32_t)strtol(argv[1], 0, 0);
	uint32_t eaddr = (uint32_t)strtol(argv[2], 0, 0);
	while (saddr <= eaddr)
	{
		pte_t *pte = pgdir_walk(kern_pgdir, (void *)saddr, 0);
		if (!pte || (!(*pte) & PTE_P))
		{
			cprintf("Page 0x%x has no mapping!\n", saddr);
			saddr += PGSIZE;
			continue;
		}
		uint32_t pa = PTE_ADDR(*pte);
		cprintf("VA 0x%x, PA 0x%x, PTE_P %x, PTE_W %x, PTE_U %x;\n",
			saddr, pa, *pte & PTE_P, *pte & PTE_W, *pte & PTE_U);
		saddr += PGSIZE;
	}
	return 0;
}

int mon_setperm(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 4)
	{
		cprintf("Type \"setperm vaddr mode perm\" to set permission\n");
		cprintf("\tmode = 0(clear), 1(set), 2(change)\n");
		cprintf("\tperm = 'P', 'W', 'U'\n");
		return 0;
	}
	uint32_t va = (uint32_t)strtol(argv[1], 0, 0);
	pte_t *pte = pgdir_walk(kern_pgdir, (void *)va, 0);
	if (!pte || (!(*pte) & PTE_P))
	{
		cprintf("Page 0x%x has no mapping!\n", va);
		return 0;
	}
	int mode = argv[2][0] - '0';
	int perm = 0;
	int plist[3] = {PTE_P, PTE_W, PTE_U};
	cprintf("BEFORE: PTE_P %x, PTE_W %x, PTE_U %x;\n",
			*pte & PTE_P, *pte & PTE_W, *pte & PTE_U);
	switch (argv[3][0])
	{
	case 'P':
		perm = 0;
		break;
	case 'W':
		perm = 1;
		break;
	case 'U':
		perm = 2;
		break;
	default:
		break;
	}
	switch (mode)
	{
	case 0:
		*pte &= ~(plist[perm]);
		break;
	case 1:
		*pte |= plist[perm];
		break;
	case 2:
		*pte ^= plist[perm];
		break;
	default:
		break;
	}
	cprintf("AFTER: PTE_P %x, PTE_W %x, PTE_U %x;\n",
			*pte & PTE_P, *pte & PTE_W, *pte & PTE_U);
	return 0;
}

int mon_dump(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 4)
	{
		cprintf("Type \"dump addrtype start end\" to dump contents in [start, end]\n");
		cprintf("\ttype: 'P' for physical address, 'V' for virtual address\n");
		return 0;
	}
	char addrtype = argv[1][0];
	uint32_t saddr = (uint32_t)strtol(argv[2], 0, 0);
	uint32_t eaddr = (uint32_t)strtol(argv[3], 0, 0);
	uint32_t content = 0;
	if (addrtype == 'P')
	{
		saddr = (uint32_t)KADDR(saddr);
		eaddr = (uint32_t)KADDR(eaddr);
	}
	while(saddr <= eaddr)
	{
		pte_t *pte = pgdir_walk(kern_pgdir, (void *)saddr, 0);
		if (!pte || (!(*pte) & PTE_P))
		{
			cprintf("0x%x: Bad address\n", saddr);
			saddr += 4;
			continue;
		}
		uint32_t addr = saddr;
		if (addrtype == 'P')
			addr  = (uint32_t)PADDR((void *)addr);
		cprintf("0x%x: 0x%x\n", addr, *((uint32_t *)saddr));
		saddr += 1;
	}
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
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
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

<<<<<<< HEAD
	if (tf != NULL)
		print_trapframe(tf);
=======
	// int x = 1, y = 3, z = 4;
	// cprintf("x %d, y %x, z %d\n", x, y, z);

	// unsigned int i = 0x00646c72;
	// cprintf("H%x Wo%s", 57616, &i);

	// cprintf("x=%d y=%d", 3);
>>>>>>> lab2_new

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
