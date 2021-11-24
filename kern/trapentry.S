/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */

/* challenge
 * add .data to TRAPHANDLER and TRAPHANDLER_NOEC to save handler address
 */
#define TRAPHANDLER(name, num)						\
.data;\
	.long name;\
.text;\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
.data;\
	.long name;\
.text;\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

/* for vector 9 and 15 */
#define pass()\
.data;\
	.long 0

.data
	.globl functions

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
functions:
.text
	TRAPHANDLER_NOEC(divide_handler, T_DIVIDE);
	TRAPHANDLER_NOEC(debug_handler, T_DEBUG);
	TRAPHANDLER_NOEC(nmi_handler, T_NMI);
	TRAPHANDLER_NOEC(brkpt_handler, T_BRKPT);
	TRAPHANDLER_NOEC(oflow_handler, T_OFLOW);
	TRAPHANDLER_NOEC(bound_handler, T_BOUND);
	TRAPHANDLER_NOEC(illop_handler, T_ILLOP);
	TRAPHANDLER_NOEC(device_handler, T_DEVICE);
	TRAPHANDLER(dblflt_handler, T_DBLFLT);
	pass();
	TRAPHANDLER(tss_handler, T_TSS);
	TRAPHANDLER(segnp_handler, T_SEGNP);
	TRAPHANDLER(stack_handler, T_STACK);
	TRAPHANDLER(gpflt_handler, T_GPFLT);
	TRAPHANDLER(pgflt_handler, T_PGFLT);
	pass();
	TRAPHANDLER_NOEC(fperr_handler, T_FPERR);
	TRAPHANDLER(align_handler, T_ALIGN);
	TRAPHANDLER_NOEC(mchk_handler, T_MCHK);
	TRAPHANDLER_NOEC(simderr_handler, T_SIMDERR);
	TRAPHANDLER_NOEC(timer_handler, IRQ_OFFSET + IRQ_TIMER);
	TRAPHANDLER_NOEC(kbd_handler, IRQ_OFFSET + IRQ_KBD);
	TRAPHANDLER_NOEC(serial_handler, IRQ_OFFSET + IRQ_SERIAL);
	TRAPHANDLER_NOEC(spurious_handler, IRQ_OFFSET + IRQ_SPURIOUS);
	TRAPHANDLER_NOEC(ide_handler, IRQ_OFFSET + IRQ_IDE);
	TRAPHANDLER_NOEC(error_handler, IRQ_OFFSET + IRQ_ERROR);

TRAPHANDLER_NOEC(syscall_handler, T_SYSCALL);

/*
 * Lab 3: Your code here for _alltraps
 */
.globl _alltraps
_alltraps:
	pushl %ds;
	pushl %es;
	pushal;	# fit the layout of struct Trapframe

	movw $GD_KD, %ax;
	movw %ax, %ds;
	movw %ax, %es;
	pushl %esp;
	call trap;
