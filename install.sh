#!/bin/sh

make
sudo rmmod geov6
sudo insmod geov6.ko
