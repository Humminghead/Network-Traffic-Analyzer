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
https://edc.intel.com/content/www/us/en/design/products/ethernet/config-guide-e810-dpdk/hugepages-setup/
