# OVERVIEW 
[![Go Report Card](https://goreportcard.com/badge/paepcke.de/hq)](https://goreportcard.com/report/paepcke.de/hq)

[paepche.de/hq](https://paepcke.de/hq/)

-   keys and signatures based on a sphincs-blake3-512
-   no new post-quantum security assumtions needed
-   hash based signatures are well studied for decades (see NIST pq shootout)
-   optional: no private key \[export|handling|storage\] (password based)
-   default-project-disclaimer: DO NOT USE IN SECURITY CRITIAL PRODUCTION YET
-   100 % pure go, minimal external imports, usable as app or api, see api.go

# INSTALL

```
go install paepcke.de/hq/cmd/hq@latest
```

### DOWNLOAD (prebuild)

[github.com/paepckehh/hq/releases](https://github.com/paepckehh/hq/releases)

# SHOWTIME 

## generate key pair \[hq identity\]

```shell
hq genrate
# Owner ID      : paepcke@example.com
# Passphrase ONE: **************
# Repeat     ONE: **************
# Passphrase TWO: **************
# Repeat     TWO: **************
# Layer  ############.#########.#######.#######.######.#####.###########.#########.#######.##.#!
# Name TAG      : TIES25-DE-NIIOAS-SO-F42EMA6WOW
# Time needed   : 1.132897239s
```

-   Public Key will be stored in ~/.hq/NameTAG, current active key will be marked via setting symbolic link 'me' -NameTAG

## sign a file

```shell
hq sign file.txt
# Owner ID      : paepcke@example.com
# Name TAG      : 6HZVBF-QJ-AFFNEA-JF-JVROQIBRRP
# Passphrase ONE: **************
# Passphrase TWO: **************
# File Name     : text.txt
# Time Stamp    : Sunday, 30-Oct-22 05:25:53 UTC [1667107553]
# Time needed   : 1.16469552ms
```

## verify a file

```shell
hq verify file.txt  
# Please unlock your HQ Identity! [pending file sign operation: text.txt]
# Owner ID      : paepcke@example.com
# Name TAG      : 6HZVBF-QJ-AFFNEA-JF-JVROQIBRRP                                             [CONFIRMED]
# File Name     : text.txt.hqs                                                               [CONFIRMED]
# Time Stamp    : Sunday, 30-Oct-22 05:25:53 UTC [1667107553]                                [CONFIRMED]
# Time needed   : 5.833229ms
```

-   [via pipe: cat ./test.text.hqs | hq] or [run signature: ./text.txt.hqs]

## sign an executable

```shell
hq sign testscript.sh
[...]
```

## run the executeable

```shell
./testscript.hqs
[...]
```

-   the executable will test its integrity, signatures and will report the state
-   will only exexcute if it finds an trusted hq identiy [public key] in your ~/.hq keystore

## sign a directory

```shell
hq sign .
# Files FAIL    : 0
# Files OK      : 4
# Files Total   : 4
# Time needed   : 61.891615ms
# Owner ID      : paepcke@example.com
# Name TAG      : 6HZVBF-QJ-AFFNEA-JF-JVROQIBRRP
# File Name     : .hqMAP.1667107763.2022-10-30T05.29.23Z.zst
# Time Stamp    : Sunday, 30-Oct-22 05:29:23 UTC [1667107763]
# Time needed   : 4.331267865s
```

-   .hqMAP.<timestamp>.zst contains the state of every file as [easy-to-use-and-verify-ieverywhere] blake3 checksum
-   .hqMAP.<timestamp>.zst.hqs signs the hqMAP

## verify a directory

```shell
echo "MODIFICATION" >text.txt
hq verify .
# File Name     : text.txt
# Error Code    : FILE MODIFIED [FILE HASH MISSMATCH]
# File Expected : ac169ead597dac88b2d7223edd85c9895392532cfc7a3c5c29a3fbe3ccba37f2
# File Found    : 5eeef57bc6267c9804f8de7f75f0fac4af3b159f04b4a8a302c28f67450ed6b3
# Files FAIL    : 1
# Files OK      : 3
# Files Total   : 4
# Time needed   : 58.889271ms
# Owner ID      : paepcke@example.com
# Name TAG      : 6HZVBF-QJ-AFFNEA-JF-JVROQIBRRP                                             [CONFIRMED]
# File Name     : .hqMAP.1667107836.2022-10-30T05.30.36Z.zst.hqs                             [CONFIRMED]
# Time Stamp    : Sunday, 30-Oct-22 05:30:36 UTC [1667107836]                                [CONFIRMED]
# Time needed   : 877.292µs
```

# SHOWTIME ADVANCED

## generate additional \[legacy\] OpenBSD signify keys and signatures

```shell
export HQ_ADD_SIGNIFY=true
hq generate
hq sign
[...]
```

## sign a directory, generate additional codereview hash \[filters the noise/signal of source code changes\]

```shell
hq c .
```

-   The additional code review hash will only change if compiler/codegeneration relevant changes where performed.
-   Changes on comments, formating, re-order of arguments, functions, renames, will not lead to a executable code & hash change.

## Unlock and lock the hq identity private key for subsequent sign operations

```shell
hq unlock
[...]
hq lock
```

## every sub-command has a one-letter-short-form

```shell
hq s .  [equals: hq sign .]
hq v .  [equals: hq verify .]
[...]
```

## what else ?

```shell
hq help
 usage: hq <action<opt:target<opt:timestamp|exec-parameter>

 action:
 [s]ign      sign mode for <target>
 [c]ode      sign mode for <target>, include additional code-review hashes
 [v]erify    verify mode for <target>
 [r]un       run .hqx exec container
 [g]enerate  generate new hq id [or: re-produce public key]
 [u]nlock    unlock id [raw sphincs key]
 [l]ock      lock [remove] cached raw sphincs key
 [p]wd       generate hq id and <targetspecific password
 [x]pwd      generate hq id and <targetspecific legacy password
 [t]est      verify crypto functions via hard-wired test vector suite
 [b]ench     benchmark
 [h]elp      show help

<hqx>|<hqs>|<dir>|<pipe>|<exec- object typ will pick the action

ENV
 FORCE_COLOR=true          color terminal output
 HQ_ADD_SIGNIFY=true       generate additional OpenBSD signify compatible .sig signatures
 HQ_SIG_ONLY=true          to sign executeables as .hqs
 HQ_MAP_ONLY=true          to generate .hqMAP files without signature
 HQ_MAP_CLEAN=true         to remove all existing .hqMAP[s] on <target>
 HQ_OWNER                  set owner for generate operations [batch mode]
```

# EXTERNAL RESOURCES 

Special thanks goes to:

* [sphincs.org](https://sphincs.org)
* [sphincs.org/resources.html](https://sphincs.org/resources.html)
* Daniel J. Bernstein, Andreas Huelsing, Stefan Koelbl, Ruben Niederhagen, Joost Rijnevel
  and Peter Schwabe: The SPHINCS+ signature framework. 2019 ACM SIGSAC Conference on Computer
  and Communications Security, CCS'19, ACM (2019), pp 2129–2146. Date: 2019-09-23 
  [pdf] (https://cryptojedi.org/papers/spx-20190923.pdf)
* [zeebo/blake3](https://github.com/zeebo/blake3) [CC0] for the blazing fast blake3 golang implementation
* [yawning/sphincs](https://github.com/yawning/sphincs256) [BSD3] for the sphincs256 init implementation

# DOCS

[pkg.go.dev/paepcke.de/hq](https://pkg.go.dev/paepcke.de/hq)

# CONTRIBUTION

Yes, Please! PRs Welcome! 
