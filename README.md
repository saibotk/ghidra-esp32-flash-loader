
# flash loader plugin for ghidra

Build with gradle

    export GHIDRA_INSTALL_DIR=/opt/ghidra/
    gradle
    
Put the ./dist/ghidra_9.1_DEV_20200613_esp32_flash_loader.zip
Into /opt/ghidra/Extensions/Ghidra/
Then enable the extension

TODO, Use Dockerfile from here https://github.com/blacktop/docker-ghidra to build the extension


If loading an elf file, load svd manually before doing analysis

https://leveldown.de/blog/svd-loader/


# FRICKEN WIERD!!!!!!
Somehow, this commit (https://github.com/austinc3030/esp32_flash_loader/commit/07cafd6590209ea8f259f3965cd7cdfe3f8372a5) causes issues between OSX and linux. Using the relative path ("../../") works on linux but breaks on OSX requiring the old "help/shared/DefaultStyle.css"????? NOT AT ALL SURE WHYYY???????
