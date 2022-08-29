# seccomp-example

Quick and dirty example to demonstrate `seccomp` behavior across `fork()` boundaries.

### Building

```
make
```

### Usage

```
Usage:
doseccomp.elf [restrict|unchanged|relax]
```

When the mode is `restrict` both the parent and the child succeed in installing their syscall filters. However the child will crash because it has reduced its permissions to disallow its call to `getpid()` even though the parent had this ability.

When the mode is `unchanged` both the parent and child install syscall filters and both have the necessary permissions to `getpid()` and succeed in running to completion.

When the mode is `relax` both the parent and the child will crash. The parent begins without permission to `getpid()` so it will crash after `wait()`-ing when it calls `getpid()`. The child will also fail because it attempts to install a syscall filter that adds `getpid()` to its list of allowed syscalls which it cannot do because it inherited an inability to access `getpid()` from its parent.
