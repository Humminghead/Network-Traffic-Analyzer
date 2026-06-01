## What is it NTA repository?

It's attempt to make powerful & easy-to-use software to monitor your entire network 

Main goals:
    
- Keep an eye on all systems, devices, traffic & more
    
- Create software for fit small & medium environments
    
- Create available the monitoring with on-premises solution

Currently, this project is at the stage of active development (**develop branch**).

## Requrements:

Packages:

- meson

- conan

## Quick start guide:

Install necessary packages:

https://docs.conan.io/2/installation.html

https://docs.conan.io/2/installation.html


Clone repository:

```

git clone https://github.com/Humminghead/Network-Traffic-Analyzer.git

```

Create conan packages:

```
conan create <project_root>/recipes/<recipe> --build=missing -pr=<your_conan_toolchain_name>
```

Build:

```
make

make install
```

## How to initialize HugePages:

List numa nodes with their cores:

```
lscpu | grep -i numa
```

### After the system has booted:

For a single-node system:

The command to use is as follows (assuming that 1024 pages are required).

```
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 
mount -t hugetlbfs nodev /mnt/huge
```

On a NUMA machine, pages should be allocated explicitly on separate nodes:

```
mkdir -p /mnt/huge 
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages 
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages 
mount -t hugetlbfs nodev /mnt/huge
```

Original paper:
https://edc.intel.com/content/www/us/en/design/products/ethernet/config-guide-e810-dpdk/hugepages-setup/
