.PHONY: clean all

all: 	pwd_guesserN pwd_guesserU

pwd_guesserU:	parallel_user.o
	gcc -o pwd_guesserU -fsanitize=address parallel_user.o -lcrypt -pthread
	
parallel_user.o:  parallel_user.c
	gcc -c -fsanitize=address parallel_user.c
		
pwd_guesserN:	parallel_number.o
	gcc -o pwd_guesserN -fsanitize=address parallel_number.o -lcrypt -pthread	
	
parallel_number.o:  parallel_number.c
	gcc -c -fsanitize=address parallel_number.c

clean:
	rm -f *~ *.o pwd_guesserU pwd_guesserN