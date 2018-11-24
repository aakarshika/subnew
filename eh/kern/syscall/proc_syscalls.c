#include <types.h>
#include <kern/errno.h>
#include <kern/syscall.h>
#include <kern/fcntl.h>
#include <kern/limits.h>
#include <kern/seek.h>
#include <kern/stat.h>
#include <kern/wait.h>
#include <lib.h>
#include <uio.h>
#include <proc.h>
#include <vfs.h>
#include <vnode.h>
#include <openfile.h>
#include <filetable.h>
#include <current.h>
#include <synch.h>
#include <copyinout.h>
#include <mips/trapframe.h>
#include <addrspace.h>
#include <thread.h>
#include <syscall.h>


int sys_getpid(int *retval)
{
	KASSERT(curproc != NULL);
	*retval = curproc->p_pid;
	return 0;
}


void sys__exit(int exitcode)
{
    	struct addrspace* as;
	struct proc* p = curproc;

    	//DEBUG(DB_EXEC, "_exit(): process %u\n",p->p_pid);
    
	KASSERT(p->p_addrspace != NULL);

    
    	as_deactivate();
    	as = proc_setas(NULL);
    	as_destroy(as);

    	proc_remthread(curthread);

    	spinlock_acquire(&p->p_lock);

    	p->p_exitval = _MKWAIT_EXIT(exitcode);
    	p->p_finished = true;
    	//V(p->p_sem);
	spinlock_release(&p->p_lock);
	
    	V( p->p_sem );
	
	//DEBUG(DB_EXEC, "_exit(): V p_sem %u\n",p->p_sem->sem_count);

	proc_destroy(p);
    	
    	thread_exit();
    	panic("_exit: thread could not exit()\n");
}


int sys_waitpid(pid_t pid,
            userptr_t status,
            int options,
	    int* retval
            )
{
   
    int result;

    struct proc* wp = curproc; // waiting  process
    struct proc* child = proc_get_process(pid);

	if(pid < 1)
		return ECHILD;
	if (options != 0)
        	return EINVAL;
	if(child == NULL) 
        {
            	DEBUG(DB_EXEC,"waitpid: invalid child pid\n");
            	return ECHILD;
        }
	if (wp != kproc && child->p_parent != wp)
    	{
        	//given pid is not of this process's child and current waiting process is not kernel process
        	DEBUG(DB_EXEC,"waitpid: ECHILD\n");
        	return ECHILD;
    	}
        if(status != NULL)
	{
		//waiting on child:
        	while(!child->p_finished)DEBUG(DB_EXEC,".");
		//proc_destroy(child);
		//P(child->p_sem); //for wait-exit logic
   		//DEBUG(DB_EXEC, "P sem %u\n",child->p_sem->sem_count); 
		//if(status != NULL){
    		spinlock_acquire(&child->p_lock);
		result = copyout(&child->p_exitval,status,sizeof(int));
	        spinlock_release(&child->p_lock);

    		if(result)
    		{
        		return EFAULT;
    		}
                //proc_destroy(child);

		//P(child->p_sem); //for wait-exit logic
                //proc_destroy(child);

    	}
	
        P(child->p_sem); //for wait-exit logic
	//proc_destroy(child);
	*retval = (int)pid;
    	return 0;
}


int sys_fork(struct trapframe* p_tf, int *retval)
{
    //DEBUG(DB_EXEC,"fork: entering\n");
    
	KASSERT(curproc != NULL);
    	KASSERT(sizeof(struct trapframe)==(37*4));
   
    	char* child_name = kmalloc(sizeof(char)* NAME_MAX);
    	strcpy(child_name, curproc->p_name);
    	strcat(child_name, "_c");

	    //Fork process:
    	struct proc* child_proc = NULL;
    	proc_fork(&child_proc);
    	if (child_proc == NULL)
    	{
        	return ENOMEM;
    	}
	strcpy(child_proc->p_name, child_name);

    	KASSERT(child_proc->p_pid > 0);
    
    	//strcpy(child_proc->p_name, strcat(curproc->p_name,"_c"));

    	struct addrspace* child_as = kmalloc(sizeof(struct addrspace));
    	if (child_as == NULL)
    	{
        	kfree(child_name);
	        proc_destroy(child_proc);
        	return ENOMEM;
    	}
    	int result = as_copy(curproc->p_addrspace, &child_as);
    	if (result)
    	{
        	kfree(child_name);
	        as_destroy(child_as);
	        proc_destroy(child_proc);
        	return result;
    	}
 	//DEBUG(DB_EXEC,"fork: addrspace copied to child as\n");
    	struct trapframe* child_tf = kmalloc(sizeof(struct trapframe));
    
	if (child_tf == NULL)
    	{
        	kfree(child_name);
	        as_destroy(child_as);
	        proc_destroy(child_proc);
        	return ENOMEM;
    	}

    	child_proc->p_addrspace = child_as;
	memcpy(child_tf, p_tf, sizeof(struct trapframe));
    	// DEBUG(DB_EXEC,"fork: tf copied\n");
    	filetable_copy(curproc->p_filetable,&child_proc->p_filetable);
    	child_proc->p_parent = curproc;
	// DEBUG(DB_EXEC,"fork: filetable copied\n");
    
    	result = (int)array_add(curproc->p_children, (void*)child_proc->p_pid, NULL);
    	if (result)
    	{
        	DEBUG(DB_EXEC,"fork: couldnt add to array\n");
       	 	return result;
    	}
        //DEBUG(DB_EXEC,"fork: p %u has child %u\n",curproc->p_pid,child_proc->p_pid);
    	result = thread_fork(child_name, child_proc, &enter_forked_process, child_tf, 1);
    
    	if (result)
    	{
        	kfree(child_name);
	        kfree(child_tf);
	        as_destroy(child_as);
	        proc_destroy(child_proc);
	        return ENOMEM;
    	}
   	//as_destroy(child_as); 
    	*retval = child_proc->p_pid;
    
    	// DEBUG(DB_EXEC,"fork: successful\n");
    	return 0;
}






int
sys_execv(const_userptr_t path, userptr_t argv)
{
	if (path == NULL)
	{
		return EFAULT;
	}
	// memory for path
	char* kernel_path = kmalloc(PATH_MAX);
	DEBUG(DB_KMALLOC,"execv: pathmax, &kernel_path %d:%p\n",PATH_MAX,&kernel_path);
	if (kernel_path == NULL)
	{
		return ENOMEM;
	}
	// copying user path into kernel
	size_t arglen;
	int result = copyinstr(path, kernel_path, PATH_MAX, &arglen);
	if (result)
	{
		return result;
	}
	if (strcmp(kernel_path,"") == 0)
	{
		return EINVAL;
	}
	
	char** user_argv = (char**) argv; //arguments gotta be char**
	userptr_t test;
	if(argv != NULL)
	{
		result = copyin((const_userptr_t)argv,&test,sizeof(userptr_t));
		if (result)
		{
			return result;
		}
	}
	int argc = 0;
	if(user_argv == NULL)
	{
		return EFAULT;
	}
	//counting args in argc
	for (argc = 0; user_argv[argc] != NULL; argc++);

	if (argc > ARG_MAX)
	{
		return E2BIG;
	}
	// copying argv from user to kernel space
	int arg_size = (argc+1) * sizeof(char*);
	char** kernel_argv = kmalloc(arg_size);
	DEBUG(DB_KMALLOC,"execv: argsize:kernel_argv %d:%p\n",arg_size,&kernel_argv);
	if (kernel_argv == NULL)
	{
		return ENOMEM;
	}
	for (int i=0; i<argc; i++)
	{
		kernel_argv[i] = kmalloc(PATH_MAX);
		DEBUG(DB_KMALLOC,"execv: pathmax:kernel_argv[?]: %d:%p\n",PATH_MAX,&kernel_argv[i]);
		result = copyinstr((const_userptr_t)user_argv[i], kernel_argv[i], PATH_MAX, &arglen);
		if (result)
		{
			return result;
		}
	}
	// NULL at the end of argv
	kernel_argv[argc] = NULL;
	// Open the program file
	char* name = kstrdup(kernel_path);
	struct vnode* v;
	result = vfs_open(name, O_RDONLY, 0, &v);
	kfree(name);
	if (result)
	{
		return ENOMEM;
	}
	// Creating new address space 
	KASSERT(proc_getas() != NULL);
	struct addrspace* existing_as = proc_getas();
	spinlock_acquire(&curproc->p_lock);
	curproc->p_addrspace = as_create();
	spinlock_release(&curproc->p_lock);
	if (curproc->p_addrspace == NULL)
	{
		vfs_close(v);
		return ENOMEM;
	}
	as_activate();

	// Loading program exec file by load-elf
	vaddr_t entrypoint;
	result = load_elf(v, &entrypoint);
	if (result)
	{
		vfs_close(v);
		return result;
	}
	vfs_close(v);

	//new user stack
	vaddr_t stackptr;
	result = as_define_stack(curproc->p_addrspace, &stackptr);
	if (result)
	{
		return result;
	}
	// Allocate space for address pointers
	char** addr_ptr = kmalloc((argc+1)*sizeof(char*));
	DEBUG(DB_KMALLOC,"execv: ?:addr_ptr %d:%p\n",(argc+1)*sizeof(char*),&addr_ptr);
	if (addr_ptr == NULL)
	{
		return ENOMEM;
	}
	for (int i=argc-1; i>=0; i--) //copying args into stack in reverse
	{
		char* arg = kernel_argv[i];
		int len = strlen(arg)+1;
		int shift = 0;//len%4;
		//if(shift ==0)	shift =4;	//4-byte aligning that did not work. 
		stackptr-= (len+shift);
		result = copyoutstr(arg, (userptr_t)stackptr, len, &arglen);
		if (result)
		{
			return result;
		}
		addr_ptr[i] = (char*)stackptr;
	}
	addr_ptr[argc] = NULL;
	
	for(int i = argc-1;i >=0;i--)
	{
		stackptr-=4;
		copyout(&addr_ptr[i], (userptr_t)stackptr, sizeof(addr_ptr[i]));
	}

	int remaining_bytes = stackptr%4; //4-byte aligning
	stackptr-=remaining_bytes;
	bzero((void*)stackptr, remaining_bytes);
	int offset = (argc+1)*sizeof(char*);
	stackptr-=offset;
	result = copyout(addr_ptr, (userptr_t)stackptr, offset);
	if (result)
	{
		return result;
	}
	vaddr_t new_argv = stackptr;
	remaining_bytes = stackptr%8; //8-byte aliging
	stackptr-=remaining_bytes;
	bzero((void*)stackptr, remaining_bytes);
	
	// Deallocate variables that were malloc-ed and are no
	// longer needed.
	as_destroy(existing_as);
        for (int i=0; i<=argc; i++)
        {
                kfree(kernel_argv[i]);
	}
	kfree(kernel_argv);
	kfree(kernel_path);
	kfree(addr_ptr);
	// Enter user mode
	enter_new_process(argc, 
			(userptr_t)new_argv,
			//(userptr_t)stackptr,
			 NULL,
			stackptr, entrypoint);
	// enter_new_process does not return, panic if reached
	panic("enter_new_process returned unexpectedly!!!\n");
	return EINVAL;
}

