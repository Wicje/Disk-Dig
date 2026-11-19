# Disk-Dig

Linux desktop data recovery app for scanning drives and raw disk images, listing recoverable files, and copying selected files to a target folder.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j8
```

## Run

```sh
./build/diskdig
```

Raw devices require root or membership in the `disk` group. Raw disk image files can be opened without elevated privileges.

## Scope

Read-only scanning of ext2/3/4, FAT32, and NTFS metadata, plus signature carving. Recovered files are copied to the chosen target folder; the source is not modified.
