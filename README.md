# LKM-Kill-SysCallHook 
LKM (linux kernel module) to hook syscall functions


Build the .ko (kernel object):
```
git clone https://github.com/Sargastico/LKM-Kill-SysCallHook.git && cd LKM-Kill-SysCallHook && make
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
