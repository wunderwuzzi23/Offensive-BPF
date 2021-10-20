# Offensive BPF experiments and programs written using libbpf-bootstrap

This repo is entirely based on the original `libbpf-bootstrap` and it's scaffolding. 


I created one new BPF program called `obpf` which hooks `getdents64` to overwrite filenames on the fly.

More details about this program in the [following blog post](https://embracethered.com/blog/posts/2021/offensive-bpf-libbpf-bpf_probe_write_user/).

```
cd src/c
make
```

Usage:

```
sudo ./obpf
```



# Credits

This folder is based on `libbpf-bootstrap` [repo](https://github.com/libbpf/libbpf-bootstrap)

1) Copyright (c) 2020, Andrii Nakryiko

BSD 3-Clause License

Copyright (c) 2020, Andrii Nakryiko
All rights reserved.

2) Copyright (c) 2020 Facebook

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */


