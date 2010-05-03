#include <inc/lib.h>

void
umain(void)
{
	int i;
	sys_set_prio(env->env_id, 1);
	for (i = 0; i < 5; i++) {
		cprintf("env_id %08x envx %d prio %d iter %d\n", env->env_id, ENVX(env->env_id), env->env_prio, i);
		sys_yield();
	}
	cprintf("All done in environment %08x.\n", env->env_id);
}
