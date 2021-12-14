---
title: "Compilers 101"
date: 2021-09-28T22:58:02Z
draft: false
cover: "/img/compiler101/compilers.png"
description: " "
tags: ["reverse-engineering", "compilers"]
categories: ["guide"]
---

# Compilers

This article is all about compilers.

For many people, a compiler is a mystery. for them, it is like a magical black box that takes the source file as an input and generates a binary file that can be executed.

However, the truth to be told, compilers are not wizards. In this article, we will start from the introduction to the front-end of a compiler from a reverse-engineering perspective.

The next articles will contain detailed explanations of the optimizer and the back-end.



## What is a compiler and how does it affect the reverse engineering process.

A compiler is a very complex piece of software, and what it essentially does is, taking one representation of a program as an input and generating a representation of the same program.

This input representation is usually the text file containing the source code that complies with the specifications of a specific high-level language. And the

Output is usually a low-level language representation of the same program.



Sounds not that complex right? Well, this is just a high-level overview. During this process of translation between different representations, the input source will have to face many algorithms, techniques employed by the compiler to optimize the low-level representation it generates. These algorithms may add more levels of complexity on top of the original code. 

And may even contain code that the developer is not intended of writing. These things make it harder for someone to read the compiler-generated code.



## Compiler architecture.

Compiler architecture mainly consists of 3 things

    - Front end
    - Optimizer
    - Back end

I this first article, let's dive into the Front end.

## The front end.

tbh, the front is the least important out of the above 3 in a reverse engineering perspective. anyway...

So what does this thing do? well, the front end is the place where the process of compilation begins. 

## Lexical analysis

Lexical analyzer is a part of the compiler front end and is responsible for tokenizing the given source file. What this means is that, when given a stream of characters, a lexical analyzer can turn that stream of characters into a set of distinct lexemes. These lexemes can

be separated by some delimiter. A token can have many lexemes, which essentially means that a token is a category of lexemes if that makes sense.

for example, following statement

  `  if ( i == 0 ) `

can be broken down into

  | lexemes    |     token        |
  |------------|------------------|
  | if         |     condition    |
  | (          |     bracket_open |
  | i          |     indetifier   |
  | ==         |     equal_sign   |
  | 0          |     integer      |
  | )          |     bracket_end  |


Tokenizing is very similar to how we break down complex sentences in natural languages. just like how a sentence is divided into different parts.

But unlike humans, to achieve this task, lexical analyzers use pattern matching algorithms and regular expressions.

It's also worth mentioning that lexical analysis or tokenizing can be done using unix utilities like FLEX and ANTLR.

## Syntax analysis

Syntax analysis is the second phase of the compiler's front end. Unlike lexical analysis, where pattern matching algorithms and regular expressions are used to identify tokens, Syntax analysis use a

concept known as Context-Free Grammar (CFGs). Context-Free Grammar is kinda similar to regular grammar but it's mainly used to describe the syntax of programming languages. basically, it's a superset of regular grammar. 

When the lexical analyzer outputs the stream of tokens, these tokens are then fed into the syntax analyzer. Then the syntax analyzer analyzes and parses the stream of tokens against different rules and

detect syntax errors in the code.

for example, `if ( i == 0 ` is passed down, it is the syntax analyzers job to report it as an error. However, some syntax analyzers are capable of continuing the parsing process even if there are syntax errors. To achieve

this, syntax analyzers use error recovery strategies.

After parsing all the syntax, the syntax analyzer should generate a parse tree. A parse tree is a representation of the production rules.

for example, applying left-derivation production rule on ` x + b - c `, resulting parse tree is

    E -> E - E

    E -> E + E - E

    E -> id + E - E

    E -> id + id - id



            E
        ---------
        |   |   |
        E   -   E
    ____|____
    |   |   |
    E   +   E

Syntax analysis can be done using YACC(Yet Another Compiler Compiler), CUP, Bison, and ANTLR.

### Abstract Synstax Trees (ASTs)

Just like a parse tree, an abstract syntax tree or AST is a graph representation of the source code. How an AST differs from a parse tree is, an AST is a simplified version of the parse tree. And in ASTs operators are internal nodes. ASTs are also considered to be the out of syntax analysis phase of a compiler.

Remember CFGs?, in modern programming languages, there are lots of things that CFGs cant express. for example type definitions. Almost every modern language allows new types. However, CFGs cannot represent new types and

their usage. ASTs can solve these problems.

Another major usage of ASTs is that a full traversal of the AST data structure represents the correctness of the program. ASTs are heavily used in semantic analysis too.

## THE END

So yeah that's it for the compiler front end. I suggest readers go through "Concepts of programming languages" for more detailed explanations.

I'll do the optimization article soon. until then... 
