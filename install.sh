#!/bin/sh

make

lsmod | grep geov6
if [ $? -eq 0 ]; then
    sudo rmmod geov6
fi

sudo insmod geov6.ko
