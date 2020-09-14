# OPC UA fuzzing example


## Building 

To reproduce the fuzzing setup described in our article you should do the following:


#### Step 0

Download sources of UA Ansi C Stack. You can do it by update submodule in this repository:
```
git submodule update --init --recursive
```

To reset code to vulnerable commit use:
```
cd UA-AnsiC-Legacy`
git reset --hard f01acfab3da583645221f9a30a9ff88af21ec1aa
```


#### Step 1

Set windows compiler to `clang` and add address sanitizer and libfuzzer flags in file `./CMakeLists.txt` 

```
set(CMAKE_C_COMPILER "C:\\Program Files (x86)\\LLVM\\bin\\clang.exe")
set(CMAKE_CXX_COMPILER "C:\\Program Files (x86)\\LLVM\\bin\\clang.exe")
set(CMAKE_CXX_FLAGS "${compile_options_CXX} ${CMAKE_CXX_FLAGS} -fsanitize=address,fuzzer")
set(CMAKE_C_FLAGS "${compile_options_C} ${CMAKE_C_FLAGS} -fsanitize=address,fuzzer")
```

#### Step 2

Comment out `main` function in `./AnsiCSample/ansicservermain.c`. Write your own target function `LLVMFuzzerTestOneInput` to fuzz "services" in `UaTestServer_SupportedServices` (in `./AnsiCSample/ansicservermain.c`). If you would like to skip this part of an excercise you can find our target function in `target-function.c`. 


#### Step 3

Some "services" require authentication to be performed first, but fortunately we can just patch authentication functions out by replacing
```
uStatus=check_authentication_token(a_pRequestHeader);
```
with 
```
uStatus = OpcUa_Good;
```
so that the next error check would get passed.

#### Step 4

Compile the project. 
```
mkdir build && cd build
cmake .. 
cmake -GNinja -DCMAKE_BUILD_TYPE=Debug ..
ninja
```

#### Step 5

After performing compilation step 4 would normally fail during linking. To fix the error and link the binary you have to edit linking arguments or use command to compile the binary:

```
cmd.exe /C "cd . && C:\PROGRA~2\LLVM\bin\clang.exe -fuse-ld=lld-link -nostartfiles -nostdlib -g -Xlinker /subsystem:console -Xclang -gcodeview -O0 -D_DEBUG -D_DLL -D_MT -Xclang --dependent-lib=msvcrtd   AnsiCSample/CMakeFiles/AnsiCServer.dir/ansicservermain.c.obj AnsiCSample/CMakeFiles/AnsiCServer.dir/browsenext.c.obj AnsiCSample/CMakeFiles/AnsiCServer.dir/browseservice.c.obj AnsiCSample/CMakeFiles/AnsiCServer.dir/init_variables_of_addressspace.c.obj AnsiCSample/CMakeFiles/AnsiCServer.dir/readservice.c.obj  -o bin\AnsiCServer.exe -Xlinker /implib:lib\AnsiCServer.lib -Xlinker /pdb:bin\AnsiCServer.pdb -Xlinker /version:0.0   lib/uastack.lib  -lws2_32.lib  -lcrypt32.lib  -lrpcrt4.lib "C:/Program Files (x86)/OpenSSL-Win32/lib/libssl.lib" "C:/Program Files (x86)/LLVM/lib/clang/10.0.0/lib/windows/clang_rt.asan_dynamic_runtime_thunk-i386.lib" "C:/Program Files (x86)/LLVM/lib/clang/10.0.0/lib/windows/clang_rt.asan_dynamic-i386.lib" -fsanitize=fuzzer "C:/Program Files (x86)/OpenSSL-Win32/lib/libcrypto.lib"  -lkernel32 -luser32 -lgdi32 -lwinspool -lshell32 -lole32 -loleaut32 -luuid -lcomdlg32 -ladvapi32 -loldnames -lmsvcrtd && cd ."
```
