# 0x41 CTF SPN server and solver

Vibecoded complete solver based on https://rkm0959.tistory.com/195

```
$ python server.py
Server started on ('0.0.0.0', 4004)!
```

```
$ python solve.py
[*] Connecting to 127.0.0.1:4004 and receiving pairs…
[*] Received 65536 pairs
[*] Building linear equations (attack 1)…
[*] Built equations: ZERO=35 ONE=29
[*] Recovering K0 by correlation (attack 2)…
[*] Using up to 8192 samples for K0 correlation…
[K0] byte 0: 31 (score=45320)
[K0] byte 1: 35 (score=45503)
[K0] byte 2: 31 (score=45202)
[K0] byte 3: 31 (score=46279)
[K0] byte 4: 39 (score=44918)
[K0] byte 5: 38 (score=45612)
[K0] byte 6: 66 (score=44956)
[K0] byte 7: 64 (score=44888)
[*] K0 = 3135313139386664
[*] Solving linear system over GF(2)…
[*] Candidate solutions: 16
[*] Verifying candidates against samples…
[+] Recovered flag (master key):
flag{151121d998fdb1a9}
```
