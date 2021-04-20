# LKM-SyscallTableHook
LKM (linux kernel module) to hook syscall functions


Build the .ko (kernel object):
```
git clone https://github.com/Sargastico/LKM-Sys_Kill-Hook.git && cd LKM-Sys_Kill-Hook && make
```

Load the kernel module:
```
sudo insmod main.ko
```

Check the kernel log for lkm output:
```
sudo tail -f /var/log/kern.log
```

Get root by sending a "kill" command with a 33 "sig" to 666 "pid":
```
kill -33 666
```
