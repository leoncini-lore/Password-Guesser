.PHONY: clean all

all: 	pwd_guesserN pwd_guesserU

pwd_guesserU:	parallel_user.o
	gcc -o pwd_guesserU parallel_user.o -lcrypt -pthread
	
parallel_user.o:  parallel_user.c
	gcc -c parallel_user.c
		
pwd_guesserN:	parallel_number.o
	gcc -o pwd_guesserN parallel_number.o -lcrypt -pthread
	
parallel_number.o:  parallel_number.c
	gcc -c parallel_number.c

clean:
	rm -f *~ *.o pwd_guesserU pwd_guesserN