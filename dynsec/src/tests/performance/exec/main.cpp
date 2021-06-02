//
//  main.cpp
//  PerfTestExec
//
//  Created by Berni McCoy on 4/18/19.
//  Copyright © 2019 Berni McCoy. All rights reserved.
//

#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <stdio.h>


// Call out to echo
void echo_exec()
{
    //pid_t parent = getpid();
    pid_t pid = fork();
    
    if (pid == -1)
    {
        // error, failed to fork()
    }
    else if (pid > 0)
    {
        int status;
        waitpid(pid, &status, 0);
    }
    else
    {
        char *argv[2] = {"/bin/echo", NULL};
        
        // we are the child
        execvp("/bin/echo", argv);
        _exit(1);   // exec never returns
    }
}
int main(int argc, const char * argv[]) {

    struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    
    for (int i=0; i<10000; i++){
        echo_exec();
    }
    
    clock_gettime(CLOCK_MONOTONIC, &tend);
    printf("batch execs took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
}
