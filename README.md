# firewall
Simple Linux firewall implemented as a kernel module. The program consists of two parts - the kernel module itself and an user space application that is used to enter firewall rules by user. Rules can also be loaded from a file. The app uses a netfilter library for packet capture and tools flex and bison for processing specified rules. See help for additional info about the usage.
