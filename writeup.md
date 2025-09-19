# 0x41 CTF SPN Writeup

Archived from https://rkm0959.tistory.com/195

2021. 1. 31. 01:58

I participated in 0x41 CTF as a member of Super Guesser, and we reached 2nd place.

This is a very rushed writeup, hope to patch it up after I take a sleep...

```python
def key_expansion(self, key):
  keys = [None] * 5
  keys[0] = key[0:4] + key[8:12]
  keys[1] = key[4:8] + key[12:16]
  keys[2] = key[0:4] + key[8:12]
  keys[3] = key[4:8] + key[12:16]
  keys[4] = key[0:4] + key[8:12]
  return keys

def apply_sbox(self, pt):
  ct = b''
  for byte in pt:
    ct += bytes([sbox[byte]])
  return ct

def apply_perm(self, pt):
  pt = bin(int.from_bytes(pt, 'big'))[2:].zfill(64)
  ct = [None] * 64
  for i, c in enumerate(pt):
    ct[perm[i]] = c
  return bytes([int(''.join(ct[i : i + 8]), 2) for i in range(0, len(ct), 8)])

def apply_key(self, pt, key):
  ct = b''
  for a, b in zip(pt, key):
    ct += bytes([a ^ b])
  return ct

def handle(self):
  keys = self.key_expansion(key)
  for i in range(65536):
    pt = os.urandom(8)
    ct = pt
    ct = self.apply_key(ct, keys[0])
    for i in range(ROUNDS):
      ct = self.apply_sbox(ct)
      ct = self.apply_perm(ct)
      ct = self.apply_key(ct, keys[i+1])
    self.send(str((int.from_bytes(pt, 'big'), int.from_bytes(ct, 'big'))))
```

## Summary of the Challenge

Basically, we are given a 4-round SPN cipher, and we have to completely find the key.
To do this, we are given 2^16 known plaintext/ciphertext pairs. We also know the sbox/pbox.

## The Attack Idea, and the SBOX

Since this is a known plaintext/ciphertext attack, we can think about linear cryptanalysis.
To do that, we have to exploit the SBOX's linear properties. After some researching on past linear cryptanalysis challenges in CTFs, I ended up at this writeup of zer0SPN by NGG. I ran the first code block to find that the SBOX was horrible beyond belief. Denoting bit(n,k) for 0≤n<2^8 as the kth bit from the left when we write n as a 8-digit binary integer, we can see that bit(n,k) and bit(sbox[n],k) are heavily correlated. This is a very simple output compared to the zer0SPN challenge, where several bits come into play at once.

This is a very promising outcome, and shows we are in the right direction. I actually thought I was done at this point :P

## Attack 1 : Recovering Linear Equations of the Key Bits

Now what we can do is view the SBOX as a simple XOR.

```python
def BIT(v, k):
  cc = bin(v)[2:].zfill(8)
  return ord(cc[k]) - ord('0')

invert = []
for i in range(0, 8):
  cnt_0, cnt_1 = 0, 0
  for j in range(0, 256):
    if BIT(j, i) == BIT(sbox[j], i):
      cnt_0 += 1
    else:
      cnt_1 += 1
  if cnt_0 > cnt_1:
    invert.append(0)
  else:
    invert.append(1)
```

Basically, with the above code, we can regard the SBOX as
*   if invert[i]=0, the SBOX does nothing to the ith bit
*   if invert[i]=1, the SBOX flips the ith bit

If we use this idea, then literally everything we do is just permuting and XOR'ing each bit.
Of course, the SBOX is not "perfectly" an XOR, but it will be biased towards it due to the properties we found.
This gives us a method to find 64 linear equations of the key bits in F2. Here's how we do it.

Let's think about the very first (0th) bit of the plaintext. This bit will
*   get XOR'ed by the first key bit of the first key
*   SBOX'ed (which can be approximated by XOR'ing invert)
*   PBOX'ed (moved to a new position, where we know)
*   and repeated like that for four times

note that we know the values we "XORed" in the SBOX, and we know the location of the initial 0th bit.
If the 0th bit ended up in the uth bit after the four PBOX applications, we can see that
`plaintext's 0th bit gets XORed to some bits we know and some key bits we don't know and becomes the ciphertext's uth bit`

Of course, this is all an approximation. The fact that remains true, is that the value of `ptxt[0]⊕ctxt[u]` will be biased towards either 0 or 1. From this, we can retrieve the XOR of key bits that was applied to the bit that was originally the 0th bit of the plaintext.

Doing the same thing for each of the 64 bits, we get 64 equations. Here's the code for the first part.

```python
def whi(idx, i): # what key bit am I actually using?
  if idx % 2 == 0:
    if i < 32:
      return i
    else:
      return 32 + i
  else:
    if i < 32:
      return 32 + i
    else:
      return 64 + i

for i in range(0, 64):
  loc, add = i, 0
  myenc = []
  myenc.append(whi(0, loc)) # key XOR
  for j in range(1, 5):
    add += invert[loc % 8] # sbox
    loc = perm[loc] # pbox
    myenc.append(whi(j % 2, loc)) # key XOR
  myenc.append(add % 2)
  myenc.append(loc)
  arr.append(myenc)

r = remote('185.172.165.118', 4004)
pt, ct = [], []
print("[+] Receving Plaintext")
for i in range(0, 65536):
  tt = r.recvline()
  tt = tt.split(b" ")
  A = bin(int(tt[0][1:-1].decode()))[2:].zfill(64)
  B = bin(int(tt[1][:-2].decode()))[2:].zfill(64)
  pt.append(A)
  ct.append(B)

ZERO, ONE = [], []
for i in range(0, 64):
  fin = arr[i][-1] # final location
  cnt_0, cnt_1 = 0, 0
  for j in range(0, 65536):
    st = ord(pt[j][i]) - ord('0')
    en = ord(ct[j][fin]) - ord('0')
    if st == (en + arr[i][-2]) % 2: # XOR of the key bits is 0
      cnt_0 += 1
    else: # XOR of the key bits is 1
      cnt_1 += 1
  print(cnt_0, cnt_1) # check bias
  if cnt_0 > cnt_1:
    ZERO.append(arr[i][:-2]) # sum of these = 0
  else:
    ONE.append(arr[i][:-2]) # sum of these = 1
```

## Attack 2 : Recovering the First Key XOR'ed

Here, we get the entire first key, giving us 64 more bits of information. This solves the challenge.
We will use the 0th bit of the plaintext as an example again. We will denote the final positions of the initial ith bit as f[i]. In other words, f[i] is simply the P-box iterated four times. We already know that ptxt[i] and ctxt[f[i]] are correlated.
However, if we knew the first byte of the first key getting XOR'ed, we can get even better correlation.
In this case, we know how the first byte of the plaintext is going to behave for the first round of encryption -
*   we know the key being XOR'ed
*   we can now directly apply the SBOX without approximating
*   we can directly apply the PBOX without any issue

At this point, the "new" value of the initial ith bit will have a better correlation with ctxt[f[i]].
You can get this intuitively, since we have used "less" approximations, or you may use the piling-up lemma.
Therefore, we can now brute force the first byte, do the above computation, and see which byte gives the best correlation.
This can be done for each byte separately, giving our 8 key bytes, or 64 bits. Here's the code.

```python
for i in range(0, 8): # ith byte
  print("[+] Guessing key", i)
  ideals = []
  for j in tqdm(range(0, 256)): # bruteforce
    cnt_ideal = 0
    for idx in range(0, 8):
      cnt_0, cnt_1 = 0, 0
      for whi in range(0, 65536): # over ptxt/ctxt pairs
        fin_loc = arr[8 * i + idx][-1]
        addv = arr[8 * i + idx][-2] - invert[idx]
        bt = BIT(sbox[int(pt[whi][8 * i : 8 * i + 8], 2) ^ j], idx) # the first round
        res = ord(ct[whi][fin_loc]) - ord('0')
        if bt == res:
          cnt_0 += 1
        else:
          cnt_1 += 1
      cnt_ideal += max(cnt_0, cnt_1) # the correlation
    ideals.append(cnt_ideal)
  mx = 0
  for j in range(0, 256): # max correlation
    mx = max(mx, ideals[j])
  print(ideals.index(mx))
```

## Finishing Touches

We can embedd every information we gathered as a system of linear equations over F2.
Solving this with SageMath, we see that there are 16 solutions for the system. We try all and see which matches the ptxt/ctxt pair.