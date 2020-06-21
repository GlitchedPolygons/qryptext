# qryptext

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/1a3b28b8f9004abbb1ee105d6eece676)](https://www.codacy.com/manual/GlitchedPolygons/qryptext?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GlitchedPolygons/qryptext&amp;utm_campaign=Badge_Grade)
[![Codecov](https://codecov.io/gh/GlitchedPolygons/qryptext/branch/master/graph/badge.svg)](https://codecov.io/gh/GlitchedPolygons/qryptext)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/qryptext/tree/master.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/qryptext/tree/master)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/qryptext/blob/master/LICENSE)
[![API Docs](https://img.shields.io/badge/api-docs-informational.svg)](https://glitchedpolygons.github.io/qryptext/files.html)


A simple, lightweight and straightforward wrapper around [liboqs](https://github.com/open-quantum-safe/liboqs) 
(from the [Open Quantum Safe project](https://openquantumsafe.org)) for encrypting and decrypting text messages using post-quantum cryptography.

Recommended usage, as also stated in the [open-quantum-safe GitHub repos](https://github.com/open-quantum-safe), is definitively in combination 
with pre-existing, battle-tested cryptography like [Elliptic Curve Cryptography](https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc) 
(e.g. [ECIES](https://github.com/GlitchedPolygons/cecies) is a good scheme for encrypting/decrypting data with it hibridly via [AES-GCM](https://tools.ietf.org/html/rfc5288)) or RSA.

---

### How to clone
`git clone --recursive https://github.com/GlitchedPolygons/qryptext.git`

### How to use
Just add qryptext as a git submodule to your project (e.g. into some `lib/` or `deps/` folder inside your project's repo; `{repo_root}/lib/` is used here in the following example).

```
git submodule add https://github.com/GlitchedPolygons/qryptext.git lib/qryptext
git submodule update --init --recursive
```

If you don't want to use git submodules, you can also start vendoring a specific version of qryptext by copying its full repo content into the folder where you keep your project's external libraries/dependencies.

**Never expose your private keys, take extra care when handling them and always clean up after doing crypto ops in C (don't leave private key buffers lying around in RAM at any point when they are not needed!).**

### Linking

If you use [CMake](https://cmake.org) you can just `add_subdirectory(path_to_submodule)` and then `target_link_libraries(your_project PRIVATE qryptext)` inside your own CMakeLists.txt file.

### Programs

There is a set of fully functional CLI programs ready to be compiled and used inside the [programs/](https://github.com/GlitchedPolygons/qryptext/tree/master/programs) directory. 
The two keygens for example create Kyber1024 (for KEM) and Falcon1024 (for signing) keypairs and export them into [stdout](https://en.wikipedia.org/wiki/Standard_streams) as a [JSON](https://www.json.org/json-en.html) string.
Check out the source files for more infos about parametrization and how to use them!
