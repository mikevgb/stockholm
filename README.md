Stockholm

The aim of this proyect is to create a program that mimics the wannacry ransomware.

1. run.sh will check and delete if exist the container called stockholm, after, it will build and open a terminal inside the container.
2. When the container is created it will copy, install and create
the required files.
3. Inside the container you can run python3 ./stockholm with this flags:
    -help or -h to show this message
    -version or -v to show program version
    -password or -p to set the encryption password and encrypt the files
    -reverse or -r to revert the encryption
    -silent or -s to avoid printing the files that are being encrypted
    Without -password or -p it will use the default password
    You can combine some of the flags, for example: ./stockholm -r -s or ./stockholm -p yourpass -r -s
