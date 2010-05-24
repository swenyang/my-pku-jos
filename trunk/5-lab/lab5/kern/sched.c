#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>

/*
// lab 4 challenge
int get_highest_envx(int x) {
	int i = x + 1, high = -1, ret = -1;
	if (x == 0) x = NENV;
	for (; i != x; i++) {
		//cprintf("%d ", i);
		if (i == NENV) {
			i = 0;
			continue;
		}
		if (envs[i].env_status == ENV_RUNNABLE
			&& envs[i].env_prio == ENV_PRIO_HIGHEST)
			return i;
		if (envs[i].env_status == ENV_RUNNABLE 
			&& envs[i].env_prio > high) {
			high = envs[i].env_prio;
			ret = i;
		}
	}
	//cprintf("ret%d ", ret);
	return ret;
}
*/

// Choose a user environment to run and run it.
void
sched_yield(void)
{
	// Implement simple round-robin scheduling.
	// Search through 'envs' for a runnable environment,
	// in circular fashion starting after the previously running env,
	// and switch to the first such environment found.
	// It's OK to choose the previously running env if no other env
	// is runnable.
	// But never choose envs[0], the idle environment,
	// unless NOTHING else is runnable.

	// LAB 4: Your code here.
	
	
	
	// exercise 1
	///*
	int i, j;
	if(curenv != NULL)
		i = ENVX(curenv->env_id);
	else
 		i = 0;
	for (j = (i + 1) % NENV; j != i; j = (j + 1) % NENV) {
		if(j != 0 && envs[j].env_status == ENV_RUNNABLE) {
			env_run(&envs[j]);
			return;
		}
	}
	if(envs[i].env_status == ENV_RUNNABLE) {
		env_run(&envs[i]);
		return;
	}
	//*/

	// challenge
	/*
	int i = get_highest_envx(ENVX(curenv->env_id));
	//cprintf("switch from %d to %d\n", ENVX(curenv->env_id), i);
	if (i > 0) {
		//cprintf("----envid---------%d\n", ENVX(envs[i].env_id));
		env_run(&envs[i]);
		return;
	}
	else if (curenv->env_status == ENV_RUNNABLE) {
		env_run(curenv);
		return;
	}
	*/

	// Run the special idle environment when nothing else is runnable.
	if (envs[0].env_status == ENV_RUNNABLE)
		env_run(&envs[0]);
	else {
		cprintf("Destroyed all environments - nothing more to do!\n");
		while (1)
			monitor(NULL);
	}
}
