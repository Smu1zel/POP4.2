# Building the patcher

1. Download [MSYS2](https://www.msys2.org/) and install it.
2. Open up MSYS2 MINGW64. To only build the patcher, you need to use pacman to install following dependencies:

```
pacman -S git mingw-w64-x86_64-gcc make
```

3. Clone the source code.

```
git clone https://github.com/Smu1zel/POP4.2
```

4. Enter the patcher directory. 

```
cd POP4.2/patcher
```

5. Compile the program.

```
make
```

The resulting binary should be in [MSYS2 install folder]/home/[your user name]/POP4.2/patcher. 
