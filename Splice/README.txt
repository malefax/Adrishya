------------------------------------------------------------------------------                  
Introduction                                                                                     
------------------------------------------------------------------------------ 
Well, well... looks like God's special child has made it — and uncovered a 
hidden treasure! You are about to uncover a kernel module that intercepts
splice() system calls and applies AES-256-CBC encryption to data transfers
between regular files.


------------------------------------------------------------------------------                  
Ksplice                                                                                      
------------------------------------------------------------------------------ 

$ cd Ksplice/ && make

$ ls
Adrishya.c   Adrishya.mod    Adrishya.mod.o  Makefile       Module.symvers
Adrishya.ko  Adrishya.mod.c  Adrishya.o      modules.order  secure.h

$ sudo insmod Adrishya.ko 


------------------------------------------------------------------------------                  
Userspace                                                                                    
------------------------------------------------------------------------------ 

$ cd .. && make

$ echo "God loves King Terry." > input.txt

$./splice input.txt output.txt


============================================================================

