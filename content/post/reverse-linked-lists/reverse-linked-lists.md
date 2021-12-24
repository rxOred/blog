---
title: "Reverse engineering Linkeds lists"
date: 2021-10-03T00:49:28Z
draft: false
cover: "/img/reverse-linkedlist/linkedlist.png"
description: "Identifying and Reverse engineering Linked List constructs"
tags: ["data-structures", "reverse-engineering", "cpp"]
readingTime: true
---

Oh hi. Personally, I'm not a big fan of competitive programming. Anyhow, I wanted to test my DSA skills so i started doing leetcode a week(or two ig)ago. And I spent an entire day solving some of those challenges. Eventually I came cross a medium level challege, named `Reorder List`. problem is pretty simple, you are given a head node of a linked list, what you have to do is kinda shuffle nodes around. 

And in this article, I'm hoping to cover everything from what is a linked list, how they are implemented in assembly to solving and reversing the solution of the above problem.

## What is it? and Implementation 

A linked list is a data structure. unlike an array where memory is organized linearly, nodes of linked list is scrattered around memory. Each of these nodes contains a pointer to the next node and thats how those scrattered nodes are located.

Lets take a linked list which stores integers as an example

Each node must contain space to store the integer and the pointer to next node. So, a connection between nodes in memory may look like this 

      0x1000                     0xabcd
      -----------------          -----------------
      |      |        |          |      |        |
      |  1   | 0xabcd | -------> |  3   | 0xdead | -------> somewhere who knows
      |      |        |          |      |        |
      -----------------          -----------------

Lets see what this looks like in code.

```cpp
   class ListNode {
      public:
         int value;
         ListNode *next;
   };
```

There's another important part of linked lists. which is the head/tail pointers. Head and tail pointers are used to track down head and tail of the linked list. which of those two is used is totally depend on the abstract data type. For example, linked list implementation of a stack may look like this


```cpp
   class LinkedList {
      ListNode *head;
      int count;
   }
```


with that, lets implement a stack data structure using linked lists.

node

```cpp
   class ListNode {
           int ln_value;
           ListNode *ln_next;
       public:
           ListNode(int value): ln_value(value), ln_next(nullptr) {}
           inline int GetValue(void) const { return ln_value; }
           inline ListNode *GetNext(void) const { return ln_next; }
           inline void SetValue(int value) { ln_value = value; }
           inline void SetNext(ListNode *next) { ln_next = next; }
   };
```

linked list

```c
   class LinkedList {
           ListNode *l_head;
           int l_item_count;
       public:
           LinkedList():l_head(nullptr), l_item_count(0) {}
           inline ListNode *GetHead() const { return l_head; }

           void Push(int value)
           {
               // however i prefer the make_shared way of doing this
               ListNode *node = new ListNode(value);
               if(l_head == nullptr) { l_head = node; }
               else {
                   node->SetNext(l_head);
                   l_head = node;
               }
               l_item_count++;
           }
           int Pop(void) 
           {
               if(l_head == nullptr) return -1;
               ListNode *node = l_head;
               l_head = l_head->GetNext();
               int value = node->GetValue();
               delete node;
               l_item_count--;
               return value;
           }
   };
```

In the above implementation, we can see that the Push takes and int as an input. Then creates a node and add that node to our linked list. The head will be pointing to the lastly added node.

Then the Pop method returns an int by removing the node at the head.

So, now we know what a linked list is. Let's look at the disassembly of this before approaching the above problem.

here's a main function.

```c
   int main(void)
   {
       LinkedList li;
       for (int i = 0; i < 5; i++){
           li.Push(i);
       }
       int c = li.Pop();
       while(c != -1) {
           printf("%d\n", c);
           c = li.Pop();
       }
   }
```

# Implementation in disassembly

So, to disassemble this snippet, Im gonna use radare since im on my linux machine rn. I ran the initial analysis, seeked to main function, and switched to the graph view.

![main](/img/reverse-linkedlist/newmain.png)

here, we can see that main function creates the stack frame and allocates space for local variables including space for our class LinkedList. Then we can see that it loads some stack address to rax register, moves it into rdi, and then call contructor for LinkedList. From that, we can assume that address loaded into rax and then into rdi as `this`.

then we can see that it sets `var_28` to 0. this must be the snippet where we set `i` to zero in our first for loop.

![pushing](/img/reverse-linkedlist/push.png)

then we can see var_28 is compared to 4, and if it is less or equal to 4, we are going to take the jump. this looks like the look termination part. then, next blob basically put `i` into edx and `this` into, rax, then we can see both of them are passed as arguements to the method `Push()`. 

Looks familiar right? of course we wrote the damn thing. However, if you are not really into C++, this `this` thing and methods might be not be familiar to you. In C++, a method is basically a function that belongs to an object/object. In this case, `Push` methods belongs to `LinkedList` class. And when calling a method, In OOP, we have to pass the pointer to an object of that class as the first arguement. this pointer is called `this`, but you cant see this in source files because that's some sorcery done by the compiler. Aaand in `_cdecl` calling convention uses `rdi` register as the first arguement. Now back to the disassembly. 

main function then increments `i` by 1, and then continue to loop until i > 4. And when that happens main function breaks out of the loop and get into the next snippet at address `0x11b0`.

![poping](/img/reverse-linkedlist/pop.png)

Here we can see the same thing but now it calls `Pop()` method. Anyway, that 0xffffffff? thats -1. this time we are iterating until `c` becomes -1. Aaa yes, it also calls printf with `c` as arguement. 

The rest of this main function is not useful to us. So lets analyze the push method :)

## Pushing and Poping

![push method](/img/reverse-linkedlist/pushmethod.png)

there's nothing magic here, it creates a stack frame and copy the arguements into its stack. then it passes 0x10 (16) to edi register and calls `new`. new is an operator in C++ for allocating memory. it accepts 1 arguement, which is the amount of memory we want to allocate. So, here we allcate 16 bytes :). 

then we see it copies rax to rbx and esi (which holds second arguement, the value we passed to Push) to eax. They are then passed to ListNode constructor. Next few lines are kinda confusing.
First `var_28` is the this pointer and we load it to rax. In the next line, we get the value at rax (this) to, well, rax. And that value is the first member of the LinkedList object, which is, as we know from the source, `l_head`.

then it check whether it is zero or not. And if `l_head` is not 0, we jump to `0x12d5`. Before we get into that stub, lets analyze the other one. 

If head equals to 0, that means the linked list is empty. therefore, since this is the first insertion, we have to set `l_head` to point to newly allocated `ListNode`. In the blob, we can see the same thing. we can see that in the next two lines that rax is set to var_28(this) and rdx is set to var_18 (ListNode we just allocated). In the next line, value at rax register, `l_head` is set to the rdx, which is the new node we allocated. :)

So if head is not equal to 0, which means that head is empty and this is not the first value that has been inserted to the list. Therefore what we have to do is, set new node's next node to `l_head` and set `l_head` point to newly allocated `ListNode` :). In the stub, we can see the same thing.

rax and rdx registers are loaded with var_18 and [var_28]. In the next few lines, rdi and rsi are set to the same values and passed as args to method `node->SetNext()`. Now SeNext method belongs to ListNode class and its `this` pointer is a `ListNode` pointer. here, in this case, rdi is set to `var_18` and rsi, second arguement is set to `l_head`. In the next few lines we can the same code sequence that we saw ealier. It sets `l_head` to this new node :).

then it increases `l_item_count` and returns in the next few lines.

So, that is it for Pushing :) Now lets see how Pop method looks like in assembly.

![pop method](/img/reverse-linkedlist/popmethod.png)

Well a stack frame... and then Pop method sets `rdi` to `this`, and check if `this->l_head` is equal to null. if it is null, it moves -1 to eax (0x1316), and then jump to function epigolue and simply returns.

On the other hand if head is not null, we save `l_head` in `var_8` (0x13d1 - 0x1324), then we load `l_head` to rdi and call `l_head->GetNext()` method to get the next node (0x1328 - 0x1332).
In the next few lines, return value (rax) of the GetNext method is set to `l_head`. it can be decompiled like `l_head = l_head->GetNext()`. Then it gets the node it previsouly saved in `var_8` and calls `GetValue()`. It also saves the return value in the stack (in var_c). then it check if the saved node is null (0x134d - 0x1354), if it it is we jump to below snippet.

![decrease count](/img/reverse-linkedlist/decrease.png)

What this stub does is, loads `[var_18] + 8` to rax register, substract 1 from rax, tore it in edx, set edx to something like `[var_18] + 8` and returns the value it stored at `var_c` from `GetValue()` call. here, `[var_18]` is the this pointer and [var_18] + 8 means the second member of the ListNode class. which is `l_item_count`. so as a summery we are decresing that value.

if the saved node is not null, then it jumps to below stub

![delete](/img/reverse-linkedlist/deleteop.png)

here it deletes (frees) `var_8`, the copy of the head node.

Now, from the above explaination, i assume that low level constructs of linked lists are clear to the reader.

## Traversal

Linked list traversal is pretty simple and there is no particular method to do this. one can use recursion. But here, im gonna write a traversal method using a for loop.

```c
    ListNode *LinkedList::GetNodeByValue(int value) const
    {
        ListNode *node = l_head;
        while(node){
            if (node->GetValue() == value){
                return node;
            }
            node = node->GetNext();
        }
        return nullptr;
    }
```

here, I have created another method, to call this i have modified the main function like shown below.

```c
    int main(void)
    {
        LinkedList li;
        for (int i = 0; i < 5; i++){
            li.Push(i);
        }
        auto node = li.GetNodeByValue(2);
        printf("%d\n", node->GetValue());
    }
```

Now let's take a look at the disassembly and try to understanding whats going on in the new method :3

![prologue](/img/reverse-linkedlist/traversemain.png)

like any other function, this one sets up a stack frame and alloacate enough space for locals. And like any other method we have encountered so far, this one too saves rdi, which is this, in a local variable (0x1162). It also stores the arg we passed in the local `var_1c`. `var_8` is loaded with `l_head` (0x1169 - 0x1170).

then that stub jumps into `0x11a2`. there, it compares `var_8` with 0. if it is 0, the jump is taken to `0x11a9`, else it continues execution on `0x1176`. 

![jumps](/img/reverse-linkedlist/jumps.png)

in the stub starts at address `0x11a9`, we can see that `var_8` is loaded into rdi and then passed into `var_8->GetValue()` method and compares return valeue in `var_1c`. next we can see a `sete` instruction, which sets al to 1 if zero flag is set (if `var_1c == var_8->GetValue()`). then it compares al register with 0 (0x1188). if `test` instruction sets 0 flag, which means, `al == 0` and therefore `var_1c != var_8->GetValue()` and program takes the jump to `0x1192`

otherwise, if result of the test instruction does not set zero flag, which means, `var_1c == var_8->GetValue()`, program continues execution from `0x118c`. 

![](/img/reverse-linkedlist/loopjmp.png)

in `0x118c`, rax is loaded with a pointer to the current node, and then it jumps to `0x11ae` and leaves. in `0x1192`, we call `var_8->GetNext()` and jump back to `0x11a2` to continue the loop.

And that is it for the traversal part.

Now let's solve the above leetcode problem.

## Solution to the problem

As previsouly mentioned, the problem is about mixing up nodes in the given linked list. for example,

if given a linked list like this, 

        [1] -> [2] -> [3] -> [4] -> [5]

you have to generate this

        [1] -> [5] -> [2] -> [4] -> [3]

Well it is bit hard at first if you think enough, its easy. Think about it like, this,

First node should be the 1st node, second node shoud be the n-1 th node, third node should be the 2nd node and fourth node should be n-2 th node and so on. And from that it is clear that we should use 2 pointers, one pointing to the first node and another one pointing to the last node. Then by interating each one of them from both first start and end, we can get the disired output.

consider the below example

1st iteration

        [1] -> [2] -> [3] -> [4] -> [5]

         ^                           ^
         |                           |
         |                           |
        1st pointer             2nd pointer


2nd iteration

        [1] -> [2] -> [3] -> [4] -> [5]

                ^             ^
                |             |
                |             |

               1st           2nd 
             pointer        pointer

3rd iteration

        [1] -> [2] -> [3] -> [4] -> [5]

                       ^
                       |
                       |
                    1st & 2nd
                     pointers

Now, the thing is, what will happen after 3rd iteration? 

well, if you continue the iteration, it will go through the nodes that we already used. So to solve this problem, we can device the linekd list into two parts. like shown below.


        [1] -> [2] -> [3] -> NULL  [4] -> [5]

So how can we do that? how can we seperate the linked list?. The easiest way I can think of is to use pointers, starting with the 1st node, increase 1st pointer by 1 node while iterating the second node by 2 nodes. consider the below example.


1st iteration

        [1] -> [2] -> [3] -> [4] -> [5]

         ^
         |
         |
      1st / 2nd
      pointer


2nd iteration

        [1] -> [2] -> [3] -> [4] -> [5]

                ^      ^
                |      |
                |      |
              1st     2nd
             pointer  pointer


3rd iteration

        [1] -> [2] -> [3] -> [4] -> [5]

                       ^            ^
                       |            |
                       |            |
                     1st           2nd 
                     pointer      pointer


See?, now we can set the next node of the node pointed by 1st node to null.

Eventhough we seperated the list, there is another problem we have to face. Some of you may have already noticed that. There is no way we can reach previous nodes from the second list since each node is pointing to the next node. So we have to reverse the second linekd list too.

Here is what we should do to re-order the linked list.



1. Seperate the list into two lists.
2. Reverse the second list
3. Start iteration from the first node of the fist list and first node of the second list(reversed list)


Here is the implementation.

```cpp
    void ReorderList(ListNode *head)
    {
        /* seperating the list */
        ListNode *f = head, *l = head;
        while(l != nullptr && l->GetNext() != nullptr){
            f = f->GetNext();
            l = l->GetNext()->GetNext();
        }

        /* saving the first node of second list */
        ListNode *node = f->GetNext();
        f->SetNext(nullptr);

        /* reversing the second list */
        ListNode *prev = nullptr;
        while(node != nullptr) {
            auto nnode = node->GetNext();
            node->SetNext(prev);
            prev = node;
            node = nnode;
        }

        /* re ordering lists */
        ListNode *start = head;
        ListNode *end = prev;
        while (start != nullptr && end != nullptr) {
            auto nnode = start->GetNext();
            start->SetNext(end);
            auto ennode = end->GetNext();
            end->SetNext(nnode);
            start = nnode;
            end = ennode;
        }
    }
```

main function
```c
    int main(void)
    {
        LinkedList li;
        for (int i = 5; i > 0; i--){
            li.Push(i);
            printf("%d ", i);
        }

        ReorderList(li.GetHead());

        putchar(10);
        auto c = li.Pop();
        while (c != -1) {
            printf("%d ", c);
            c = li.Pop();
        }
        putchar(10);
    }
```

## Reverse engineering the solution

Now its time to see how the solution code looks like in assembly :).

![re order list](/img/reverse-linkedlist/reorder.png)

oh look at those cute little variable name that radare has analyzed for us. Same as the ones that we used in our code right?. Well i compiled it with -g flag this time hehe :3

Anyway, in above stub, we set `f` and `l` with `head` (rdi) and jump to `0x1216`.

![0x1216](/img/reverse-linkedlist/reorder-jmp.png)

this is just a simple comparison, the stub compares `l` with 0 and jumps to `0x1235` if comparison yeilds zero.

else we jump to below stub

![0x121d](/img/reverse-linkedlist/comparefalse.png)

there we call `l->GetNext()` and check if the return value is null. if it is null, it jumps to `0x1235`. else, to `0x122e`.

![0x1235](/img/reverse-linkedlist/1235.png)

both of above snippets does nothing but jump to `0x123a`. Oh, `0x122e` set eax to 1.

In `0x123a`, there is a `test al, al` instruction which checks if any of the above comparisons leads to a null, which means if `l == null` or `l->GetNext() == null`.

if not, a jump will not be taken and execution will continue to `0x11ee`.

![0x11ee](/img/reverse-linkedlist/11ee.png)

`0x11ee` calls `f->GetNext()` (0x11ee - 0x11f5) and stores resulting value at `f`. So it basically does `f = f->GetNext()`.

then at address `0x11fe`, we can see `l` is copied to rax, which is then passed to `GetNext()` method as this parameter. return value `GetNext()` is then passed as this parameter to the `GetNext` method and `l` is assigned with the return value. So the whole thing can be represented as `l = l->GetNext()->GetNext()`. then it continues to loop until `l` or `l->GetNext()` is nullptr.

if any of above comparisons become null, loop ends and jump at `0x123c` wont be taken. `node` is assigned with `f->GetNext()` (0x123e - 0x124a). then rsi is loaded with 0 (or null). Then rdi is assigned with rax, which is `f`. then there is a call to `SetNext()`. So the function may look like this in C. `f->SetNext(NULL)`. Then we can see `prev` is assigned with 0 following a jump to `0x129c`.

![0x129c](/img/reverse-linkedlist/0x1239.png)

instruction at address `0x129c` check whether `node` is null. if it is not, jump is taken to `0x1269`. first 4 lines call `node->GetNext()` and save return value in `var_8`. then node's next is set to `prev`. remember? which is intially null (0x1279 - 0x1287). And from 0x128c to 0x1298, it simply sets `prev` to `node` and `var_8` (node->GetNext()) to `node`.

the loop continues until `node == null`.

When the termination condition is met, rip will get to `0x12a3`, where it assignes `start` with head and `prev` with `end`.

![](/img/reverse-linkedlist/1111.png)

then there is this series of comparisons. first one compares `start` with 0 and the next one compares `end` with 0. And if any of them is 0 (or null), it jumps to `0x1319` and exits.

![](/img/reverse-linkedlist/1223.png)

from address `0x12b5` to `0x12c1`, what the code does is it simply gets next node of the `start` and move it to `nnode`. from `0x12c5` to `0x12d3`, code sets `start`'s next node to `end` using `start->SetNext(end)`.

next, rdi is loaded with end and passed to `GetNext()` method and the return value is stored in `ennode`. In the next few lines, `nnode` and `end` are loaded into rsi and rdi. then they are passed down to SetNext() method, which may look like this `end->SetNext(nnode)`. then we can see `start` is assigned with `nnode` and `end` is assigned with `ennode` and continue to loop until termination condition is met, `start == nullptr || end == nullptr`

and yeap that's it. First it saves next nodes of the `start` and the `end` in two locals named `nnode` and `ennode`. then `Start` node's next is set to `end` and its next is set to `nnode` (prev next node of the `start`). Then `start` and `end` are set to `nnode` and `ennode` to continue the loop :).

    loop:
        if start == null or end == null:
            return
        nnode   <--- save start->GetNext()
        ennode  <--- save end->GetNext()
        set start->next = end
        set end->next   = nnode
        set start = nnode
        set end   = ennode
        jump loop


Oh my freaking god i spent two days writing this damned article. I guess that is it. I hope yall understood what i did here :3

#Spread Anarchy!
