#include <stdio.h>
#include <unistd.h>
 int
main(void)
{
    int status;
    pid_t pid = fork();
     if(pid != 0)
    {
	waitpid(pid,&status,0);
    }
    return(status);
}
