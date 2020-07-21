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
