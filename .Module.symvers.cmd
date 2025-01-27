cmd_/home/malefax/Adrishya/Module.symvers := sed 's/\.ko$$/\.o/' /home/malefax/Adrishya/modules.order | scripts/mod/modpost -m -a  -o /home/malefax/Adrishya/Module.symvers -e -i Module.symvers   -T -
