mkdir -p ./build/service
mkdir -p ./build/download
gcc ./src/local.c -fno-stack-protector -no-pie -m32 -Wno-address-of-packed-member -o build/download/program
gcc ./src/remote.c -fno-stack-protector -no-pie -m32 -Wno-address-of-packed-member -o build/service/program
