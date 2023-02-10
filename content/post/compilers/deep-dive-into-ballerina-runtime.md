---
title: "Deep Dive Into Ballerina Runtime"
date: 2023-02-03T16:28:21+05:30
draft: true
description: "diving deep into runtime of ballerina language"
tags: ["compilers"]
readingTime: true
---

# Table of Content

1. [Introduction](#introduction)
2. [Samples and Source code](#samples-and-source-code)
3. [Environment](#environment)
   1. [Installing Ballerina](#installing-ballerina)
   2. [Building nballerina](#installing-nballerina)
4. [Overall Architecture](#overall-architecture)
5. [Next Steps](#next-steps)

# Introduction

Ballerina is a cloud native language developed by a Sri Lankan company, which is the main reason made me wanna look into it. When I first heard about the project, I was pretty surprised to say the least. Because projects like this are somewhat uncommon among companies here.

Stable version of the language runs on JVM. However, what took my interest is their native compiler. I've been following its development since last year, when the main repository was nballerina-cpp.

Anyways, in this series of smol articles, Im gonna dive deep into nballerina runtime.

# Samples and Source code

[nballerina source code]()

[repo containing all the scripts that I'll be using]()

# Environment

To build nballerina project, first we need to setup few things including ballerina itself.

## Installing Ballerina
nballerina's compiler is written in the language itself, therefore first we need the ballerina distribution package. It is better to clone this from github and build it yourself.

```bash
git clone --recursive git@github.com:ballerina-platform/ballerina-distribution.git
```

ballerina uses gradle

```bash
cd ballerina-distribution && ./gradlew build
```

## Building nballerina

Now we can clone nballerina from its official repo

```bash
git clone git@github.com:ballerina-platform/nballerina.git
```

to build nballerina compiler

```bash
cd nballerina/compiler && bal build
```

to build ballerina runtime and examples

```bash
cd .. && make all
```

# Overall Architecture

To give a summery, nballerina is a ccompiler front-end that works with llvm as a backend. This front-end is written in ballerina language itself and is located in the `./compiler` directory. Above `bal build` command is used to compile the source and translate it to a `.jar` file, which then can be used with a java virtual machine to compile ballerina source files into llvm IR files (`.ll`).

```ballerina
// hello.bal

import ballerina/io;

public function main() {
	io:println("hello ballerina");
}
```

to compile the above source into llvm IR.

```bash
java -jar nballerina.jar <src>.bal
```

The above command generates 2 files. One is `<src>._init.ll` and the other is `<src>.ll`, and both of these are in llvm IR.

## <src>._init.ll file

If we open up the file with the extension `._init.ll`,

```llvm
@_Bi04root0 = constant {i32, i32, i64, i8 addrspace(1)*(i8 addrspace(1)*, i64)*, i64(i8 addrspace(1)*, i64, i8 addrspace(1)*)*, i64(i8 addrspace(1)*, i64, i8 addrspace(1)*)*, i64(i8 addrspace(1)*, i64)*, i64(i8 addrspace(1)*, i64, i64)*, i64(i8 addrspace(1)*, i64, i64)*, double(i8 addrspace(1)*, i64)*, i64(i8 addrspace(1)*, i64, double)*, i64(i8 addrspace(1)*, i64, double)*, i64, {i32}*, [0 x i64]} {i32 0, i32 0, i64 0, i8 addrspace(1)*(i8 addrspace(1)*, i64)* @_bal_list_generic_get_tagged, i64(i8 addrspace(1)*, i64, i8 addrspace(1)*)* @_bal_list_generic_set_tagged, i64(i8 addrspace(1)*, i64, i8 addrspace(1)*)* @_bal_list_generic_inexact_set_tagged, i64(i8 addrspace(1)*, i64)* @_bal_list_generic_get_int, i64(i8 addrspace(1)*, i64, i64)* @_bal_list_generic_set_int, i64(i8 addrspace(1)*, i64, i64)* @_bal_list_generic_inexact_set_int, double(i8 addrspace(1)*, i64)* @_bal_list_generic_get_float, i64(i8 addrspace(1)*, i64, double)* @_bal_list_generic_set_float, i64(i8 addrspace(1)*, i64, double)* @_bal_list_generic_inexact_set_float, i64 262143, {i32}* null, [0 x i64] []}
declare i8 addrspace(1)* @_bal_list_generic_get_tagged(i8 addrspace(1)*, i64)
declare i64 @_bal_list_generic_set_tagged(i8 addrspace(1)*, i64, i8 addrspace(1)*)
declare i64 @_bal_list_generic_inexact_set_tagged(i8 addrspace(1)*, i64, i8 addrspace(1)*)
declare i64 @_bal_list_generic_get_int(i8 addrspace(1)*, i64)
declare i64 @_bal_list_generic_set_int(i8 addrspace(1)*, i64, i64)
declare i64 @_bal_list_generic_inexact_set_int(i8 addrspace(1)*, i64, i64)
declare double @_bal_list_generic_get_float(i8 addrspace(1)*, i64)
declare i64 @_bal_list_generic_set_float(i8 addrspace(1)*, i64, double)
declare i64 @_bal_list_generic_inexact_set_float(i8 addrspace(1)*, i64, double)
declare void @_B04rootmain()
define void @_bal_main() {
  call void @_B04rootmain()
  ret void
}
```

Anyone famililar with little bit of llvm can easily understand above snippet. There, we can see a function called `_bal_main`. This function in turn calls another function declared `_B04rootmain`. However, there is llvm for implementation of that function as well as for our main fuction. Therefore it is safe to assume that this rootmain is in fact, our main function, or at least calls it.

To get a clear view, we can refer the source code.

```c
// nballerina/runtime/main.c

int main() {
    _bal_stack_guard = __builtin_frame_address(0) - STACK_SIZE;
    _bal_main();
    return 0;
} 
```

so this doesnt really give us any big clues on how our code gets executed but now we know for sure that the first few lines of code that's gonna get executed is initialization of stack guard and call to function `_bal_main`, which we saw earlier.

Note that we might wanna pay attention to this stack guard implementation later on.

## <src>.ll file

Lets take a look at the other file nballerina compiler generated for us.

```llvm
// hello.ll

@_bal_stack_guard = external global i8*
@_Bi04root0 = external constant {i32}
@.str0 = internal unnamed_addr constant {i16, i16, [20 x i8]} {i16 15, i16 15, [20 x i8] c"hello ballerina\00\00\00\00\00"}, align 8
[...]
declare void @_Bb02ioprintln(i8 addrspace(1)*)
define void @_B04rootmain() !dbg !5 {
  %1 = alloca i8 addrspace(1)*
  %2 = alloca i8 addrspace(1)*
  %3 = alloca i8
  %4 = load i8*, i8** @_bal_stack_guard
  %5 = icmp ult i8* %3, %4
  br i1 %5, label %16, label %6
[...]
```

`.str0` is the hello world string we had in our source file. However, we dont exactly know how ballerina works with strings (might be the next topic I'll go through).

In addition to that, definition for `_B04rootmain` function referenced in the `hello._init.ll` file. This as far as we can see, reflects the code we wrote in the source file's main function. 

At the bottom of `hello.ll` file, we can see the debug information nballerina compiler has generated for us.

```llvm
// hello.ll

[...]
!llvm.module.flags = !{!0}
!llvm.dbg.cu = !{!2}
!0 = !{i32 2, !"Debug Info Version", i32 3}
!1 = !DIFile(filename:"hello.bal", directory:"")
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false)
!3 = !DISubroutineType(types: !4)
!4 = !{}
!5 = distinct !DISubprogram(name:"main", linkageName:"_B04rootmain", scope: !1, file: !1, line: 3, type: !3, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !6)
!6 = !{}
!7 = !DILocation(line: 0, column: 0, scope: !5)
!8 = !DILocation(line: 3, column: 16, scope: !5)
!9 = !DILocation(line: 4, column: 12, scope: !5)
!10 = !DILocation(line: 4, column: 1, scope: !5)
[...]
```

Line !5 of the above snippet confirms out assumption that `main` function is in fact, `rootmain`.

## generation of llvm IR

By looking at the `/compiler` source, we can get a clear idea how above two files are being generated.

```ballerina
// main.bal

public function main(string[] filenames, *Options opts) returns error? {
	[...]
    foreach string filename in filenames {
        var [basename, ext] = basenameExtension(filename);
        if ext == SOURCE_EXTENSION {
            CompileError? err = compileBalFile(filename, basename, check chooseOutputBasename(basename, opts.outDir), nbackOptions, opts);
            if err is err:Internal {
                panic error(d:toString(err.detail()), err);
            }
			[...]
        }
        else if ext == TEST_EXTENSION {
            check compileBaltFile(filename, basename, opts.outDir ?: check file:parentPath(filename), nbackOptions, opts);
        }
    [...]
```

for each source file that are given as input to the nballerina compiler, it checks if extension is `.bal` (`SOURCE_EXTENTION`) or `.balt` (`TEST_EXTENSION`), in which the latter is the extension for ballerina test files. Then there's somewhat common few lines of code for both conditions, a call to `compileBalFile / compileBaltFile`, passing filename, filename without extension (basename) and optional output directory and other few options as arguments.

```ballerina
// compile.bal

function compileBalFile(string filename, string basename, string? outputBasename, nback:Options nbackOptions, OutputOptions outOptions) returns CompileError? {
    CompileContext cx = new(basename, outputBasename, nbackOptions, outOptions);
    front:ResolvedModule mod = check processModule(cx, DEFAULT_ROOT_MODULE_ID, [ {filename} ], cx.outputFilename());
    check mod.validMain();
    check generateInitModule(cx, mod);
}
```

`compileBalFile` is a fairly simple function. Honestly I expected a 500 lines of long function. 

First above function does some checks, most of which are not important at the moment, and calls `generateInitModule` with `CompileContext` and `ResolveModule`as parameters. 

```ballerina
// compile.bal

function generateInitModule(CompileContext cx, front:ResolvedModule entryMod) returns CompileError? {
    LlvmModule initMod = check cx.buildInitModule(filterFuncs(entryMod.getExports()));
    string? initOutFilename = cx.outputFilename("._init");
    if initOutFilename != () {
        check outputModule(initMod, initOutFilename, cx.outputOptions);
    }
}
```

It is clear from the above snippet that this function is the one that is reponsible for creating the file with `._init.ll` extension, to the same file which they refer to as init module.
Note that there is more to this funciton which we can simply ignore for now, such as what is this `LlvmModule` class and `CompileContext`. `ouputModule` function can be our next point of interest.

```ballerina
// output.bal

# The preferred output extension for the output filename.
const OUTPUT_EXTENSION = ".ll";

type OutputOptions record {
    string? target = ();
};

function outputModule(LlvmModule llMod, string outFilename, OutputOptions options) returns io:Error? {
    string? target = options.target;
    if target != () {
        llMod.setTarget(target);
    }
    return llMod.printModuleToFile(outFilename);
}
```

See the `OUTPUT_EXTENSION` is set to `.ll`. function `outputModule` takes `LlvmModule` as the first argument and outputs the file `outFilename` using `llMod.printModuleToFile` method, which simply a file i/o function.

## llvm bytecode files

Those two files generated by nballerina.jar should then be linked with `/runtime/balrt_inline.h` to generate llvm bytecode file per each IR file.

`/runtime/balrt_inline.h` is the main header file of the runtime. This file, along with other `.h` files make up the file `/runtime/balrt_inline.bc`, which is a llvm bytecode file (`.bc`).

This bytecode file contains all the code that is necessary to run a ballerina source file compiled with nballerina compiler. In order for this to work, the compiler generated `.ll` files should also be converted into `.bc` with `/runtime/balrt_inline.bc` linked to it.

This can be done using llvm-link.

```bash
llvm-link hello._init.ll  ~/repos/nballerina/runtime/balrt_inline.bc -o hello._init.bc
llvm-link hello.ll ~/repos/nballerina/runtime/balrt_inline.bc -o hello.bc
```

llvm-link generates llvm bytecode files by linking the input IR file with ballerina runtime header file.

llvm bytecode files are basically bullshit unreadable version of IR so we wont be looking at those since there's simply no use.

# Next Steps

We went through some small components of ballerina runtime and compiler in this article. In the next one, we will explore `LlvmModule` and `CompileContext`.
