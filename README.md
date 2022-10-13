# Wisp
* Wisp is a stateful coverage-based greybox fuzzer based on AFLNET and some mechanisms in SnapFuzz. 
* Wisp checks time cost in different fuzzing stages by profiling the AFLNET fuzzer and uses multiple mechanisms to improve fuzzing throughput, including shared memory-based socket replacement, extra control socket, and dynamic affinity.
* This fuzzer name comes from my favorite warframe [Wisp](https://warframe.fandom.com/wiki/Wisp), which has abilities to share buff with allies and increase speed.

## System architecture
![](https://i.imgur.com/9oiHcvf.png)

## How to build
### Prequisites
Prepare socket shared library.
```
git clone https://github.com/John6090212/socket_hook.git
cd socket_hook
make
```
### Wisp
Please reference the installation guide in [AFLNET](https://github.com/aflnet/aflnet#installation-tested-on-ubuntu-1804--1604-64-bit).

## Usage
* Now only support testing Dnsmasq(v2.73rc6), TinyDTLS(06995d4) and Dcmqrscp(7f8564c).
* Can run AFLNET with the same command as AFLNET.
* Wisp environment variable:
    * **SERVER**: indicates testing server, options include `DNSMASQ`,`TINYDTLS` and `DCMQRSCP`.
    * **AFL_PRELOAD**: specify path of [socket shared library](https://github.com/John6090212/socket_hook).
    * **USE_AFLNET_SHARE**: set to `1` to enable Wisp. If you want to use AFLNET, just omit these environment variables and use the same command as AFLNET.
* Example command:
```
SERVER=DNSMASQ AFL_PRELOAD=<socket_hook.so path> USE_AFLNET_SHARE=1 afl-fuzz -m none -d -i <input directory> -o <output directory> -N tcp://127.0.0.1/5353 -P DNS -D 10000 -K -R ./dnsmasq
```


## Reference
[1] Huang, Guan-Zhang and Huang, Chun-Ying. "Wisp: On the Performance Profiling and Improvement of Fuzzing for Network Protocols" (2022). [[Thesis](https://etd.lib.nctu.edu.tw/cgi-bin/gs32/tugsweb.cgi?o=dnctucdr&s=id=%22GT073095550020%22.&searchmode=basic)]
[2] V. -T. Pham, M. Böhme and A. Roychoudhury, "AFLNET: A Greybox Fuzzer for Network Protocols," 2020 IEEE 13th International Conference on Software Testing, Validation and Verification (ICST), 2020, pp. 460-465. [[Paper](https://ieeexplore.ieee.org/document/9159093)]
[3] Anastasios Andronidis and Cristian Cadar. "SnapFuzz: High-Throughput Fuzzing of Network Applications". In: ACM SIGSOFT International Symposiumon Software Testing and Analysis. 2022. [[Paper](https://srg.doc.ic.ac.uk/files/papers/snapfuzz-issta-22.pdf)]
