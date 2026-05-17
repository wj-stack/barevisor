# Barevisor

A bare minimum hypervisor on AMD and Intel processors for learners.


## Features

- ✅ Uses stable Rust🦀
- ✅ Covers both AMD and Intel processors
- ✅ Compiles into UEFI and Windows drivers
- ✅ Runs on Bochs and VMware with one shortcut key
- ✅ Supports select hardware models
- ✅ Builds on 🪟Windows, 🍎macOS and 🐧Ubuntu
- ✅ Comes with extensive comments


## Motivation

The primary goal of this project is to explore the possibilities of writing a hypervisor in stable Rust and designs to abstract differences between AMD-vs-Intel and UEFI-vs-Windows.

As a secondary goal, it aims to be an additional resource for learning how hardware-assisted virtualization technologies on x86 work and can be used to "hyperjack" UEFI and Windows.


## Package organization

The project contains two workspaces: `src/windows/` and `src/uefi/`, building the hypervisor as a Windows kernel driver and UEFI driver, respectively. Both workspaces depend on `src/hvcore/`, the core, OS agnostic hypervisor implementation as illustrated below:

```
    windows --\
               +-- (links) --> hvcore
    uefi -----/
```

You can build `src/windows/` only on Windows, while `src/uefi/` is cross-platform:

| Dev. env. | `src/windows/` | `src/uefi/` |
|-----------|----------------|-------------|
| Windows   | ✅            | ✅          |
| Ubuntu    | ❌            | ✅          |
| macOS     | ❌            | ✅          |

See [windows/README.md](src/windows/README.md) and [uefi/README.md](src/uefi/README.md)
for detailed build and test instructions.


## Acknowledgement

[memN0ps](https://github.com/memN0ps)'s Rust hypervisor projects substantially inspired and helped me get started with this work. I encourage you to study those projects as additional resources. Some code in the Barevisor project is heavily influenced by and may even be copied from their work even though it is not mentioned at each place.


## Non-goals

This project is optimized for the above-mentioned goals, and thus, features some might expect or think to be essential are missing, for example:

- Security

    Barevisor does not attempt to protect itself from the guest or DMA. The Windows version even depends on the guest-controlled memory.

- Useful functionality

    The only functionality Barevisor offers is hypervisor name reporting via the CPUID instruction. It provides no feature like guest inspection or hardening.

- Greater compatibility

    Barevisor's primary functional goal is to hyperjack and boot UEFI and Windows on VMware, Bochs, and select hardware models. It handles other scenarios only when implementation is simple enough.

Having written hypervisors many times for teaching, it is fair to say that one of the most challenging parts of learning hardware-assisted virtualization technologies is getting started and understanding the foundation. As you get through this phase, learn the building blocks, and be motivated, it is easier to start working on covering the listed missing features as you need.

If you wish to learn more about those missing features, ask me questions or for further learning references. I also offer a [4-day long training course](https://tandasat.github.io/) covering many of those in depth.


## Supported hardware models

- Intel: [PICO-MTU4-SEMI](https://www.aaeon.com/en/product/detail/pico-semi_pico-mtu4-semi)
- AMD: [LLM1v6SQ](https://simplynuc.com/product/llm1v6sq/)
