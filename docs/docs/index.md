
Kanawha Kernel Documentation
============================

Welcome to the Kanawha Kernel!
This is a simple hobby kernel I (Kevin) am writing in my free time.

- [Buildsystem Overview](./buildsystem/overview.md)
- [Driver Interfaces](./interfaces/index.md)
- [System Calls](./syscalls/index.md)
- [Architecture Specific Docs](./arch/index.md)

Kanawha is not *efficient*. There are many many levels of indirection do not have a fantastic reason
for existing. For example, there is an interface to allow multiple "page_allocator's" to exist in the 
system at once (this is pretty useless and slows down the entire system). But it means that you can play
around with different schemes for how to allocate physical pages. If you have some bug, and you suspect it's
the page allocator, you can just swap out the complicated buddy allocator for a dead simple slab allocator
and see if the bug is still there. You can run two completely different allocators for different regions of
memory, and the rest of the kernel will take advantage of both because they get presented through a single API.
And most of all it just makes the process of toying with the kernel and trying out dumb ideas a bit easier, which
is really what this hobby project is all about.

