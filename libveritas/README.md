# libveritas

Standalone build and packaging for the Veritas identity client library.

## Build (standalone)

```bash
conan install . -of build -s build_type=Debug
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake
cmake --build build
```

## Package with Conan

```bash
conan create .
```

## Consume from another project

In a separate project, add `libveritas/0.1.0` to your `conanfile.txt`,
run `conan install`, and link the `veritas` target from CMake:

```cmake
find_package(libveritas REQUIRED CONFIG)
target_link_libraries(my_app PRIVATE veritas)
```
