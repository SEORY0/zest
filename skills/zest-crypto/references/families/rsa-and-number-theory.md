# RSA and number theory

Apply the six [literature and adaptation gates](../literature.md) and keep the
[machine catalog](../attack-cards.json) authoritative for hard eligibility.

## `rsa.wiener.small-d`

- **Observable signals:** One RSA modulus `n`, public exponent `e`, and often a large
  observed `e/n` ratio. The ratio only ranks; it does not prove a small `d`.
- **Equations:** For convergents `k/d` of `e/n`, test `(ed-1)/k=phi`,
  `S=n-phi+1`, and `S^2-4n=t^2`; then `p=(S+t)/2`, `q=(S-t)/2`.
- **Hard assumptions:** The RSA factors are suitably balanced and `d` is inside the
  paper's sufficient small-exponent regime. The catalog does not claim the bound is
  necessary.
- **Cheapest falsifier:** Scan at most 4096 convergents and demand distinct proven-prime
  factors whose product is exactly `n`.
- **Expected cost:** Low; continued fractions and integer square roots.
- **Solver adaptation:** Use `assets/solver-templates/rsa_wiener.py`; retain its factor
  proof domain, convergent cap, ciphertext bound, and unsupported-domain result.
- **Failure interpretation:** No factor-bearing convergent rejects this card under the
  recorded cap; it does not prove the absence of other small-private-exponent attacks.
- **Proof:** Verify `pq=n`, `ed=1 mod (p-1)(q-1)`, and decrypt/re-encrypt the ciphertext.
- **Primary citation:** Wiener, *Cryptanalysis of short RSA secret exponents*,
  DOI `10.1109/18.54902`, 1990.
- **Local package example:** `assets/solver-templates/rsa_wiener.py:L1-L241` proves the
  packaged implementation boundary; it is not represented as a remote challenge pin.

## `rsa.common-modulus.coprime-exponents`

- **Observable signals:** One scalar modulus, two aligned ciphertexts, two public
  exponents, an explicit same-message fact, and `gcd(e1,e2)=1`.
- **Equations:** Find `a,b` with `ae1+be2=1`; recover
  `m=c1^a c2^b mod n`, using modular inverses for negative coefficients.
- **Hard assumptions:** Both ciphertexts encode the same unpadded representative modulo
  the same `n`; exponents are coprime; ciphertexts needed with negative powers are units.
- **Cheapest falsifier:** Check alignment, `gcd(e1,e2)`, and invertibility before any
  exponentiation.
- **Expected cost:** Low; one extended gcd, at most two inverses, and two exponentiations.
- **Solver adaptation:** Use `assets/solver-templates/rsa_common_modulus.py` with exactly
  two exponents/ciphertexts and the scalar modulus.
- **Failure interpretation:** The bundled template stops with
  `non-invertible-ciphertext`; it does not emit factor evidence. A caller may separately
  compute and prove a non-trivial gcd route. Non-coprime exponents or different messages
  reject the direct common-modulus equation.
- **Proof:** Check `m^e1=c1 mod n` and `m^e2=c2 mod n`.
- **Primary citation:** DeLaurentis, *A further weakness in the common modulus protocol
  for the RSA cryptoalgorithm*, DOI `10.1080/0161-118491859060`, 1984.
- **Local package example:** `assets/solver-templates/rsa_common_modulus.py:L1-L202`.

## `rsa.hastad.broadcast`

- **Observable signals:** At least three aligned ciphertexts of one message, exponent
  three, distinct moduli, and a derived pairwise-coprime fact.
- **Equations:** CRT gives `C=m^3 mod N` for `N=product(n_i)`; in the covered sufficient
  case `m^3<N`, so `m` is the exact integer cube root of `C`.
- **Hard assumptions:** This v1 card intentionally requires `e=3`, at least three
  aligned samples, pairwise-coprime moduli, and an unpadded common representative.
- **Cheapest falsifier:** Pairwise gcd followed by CRT and an exact cube-root check.
- **Expected cost:** Low; bounded CRT product, exact integer root, and public equations.
- **Solver adaptation:** Use `assets/solver-templates/rsa_hastad.py`; set an explicit
  maximum root size and retain the modulus-count/product caps.
- **Failure interpretation:** The bundled template stops with `non-coprime-moduli`; it
  does not return factor evidence. A separately proved shared gcd may route to
  factorization. An inexact root rejects direct broadcast recovery; never round it.
- **Proof:** Require `m^3` to equal the CRT integer before reduction and reproduce every
  ciphertext modulo its modulus.
- **Primary citation:** Håstad, *Solving simultaneous modular equations of low degree*,
  DOI `10.1137/0217019`, 1988.
- **Local package example:** `assets/solver-templates/rsa_hastad.py:L1-L223`.

## `rsa.franklin-reiter.related-message`

- **Observable signals:** One modulus, public exponent in the deliberately bounded set
  `{3,5,7}`, two ciphertexts, and an explicit known affine relation
  `m2=a*m1+b mod n`.
- **Equations:** In `(Z/nZ)[X]`, use `f1=X^e-c1` and
  `f2=(aX+b)^e-c2`; the expected monic gcd is `X-m1`.
- **Hard assumptions:** The relation and alignment are exact, `e` is one of `3,5,7`,
  `a` is usable in the stated relation, and the modular polynomial gcd exposes a linear
  factor. This card makes no claim for arbitrary “small” exponents.
- **Cheapest falsifier:** Compute a degree-at-most-seven gcd and reject a non-linear gcd
  or a root that fails either ciphertext equation.
- **Expected cost:** Medium; small-degree polynomial arithmetic over a composite ring.
- **Solver adaptation:** Write a bounded Sage solver with a monic Euclidean gcd. Surface
  every failed coefficient inversion and gcd it with `n` instead of hiding zero divisors.
- **Failure interpretation:** A non-unit may factor `n`; a higher-degree/constant gcd
  rejects this exact relation but not other related-message methods.
- **Proof:** Verify the affine relation and both RSA congruences for the recovered pair.
- **Primary citation:** Coppersmith, Franklin, Patarin, and Reiter, *Low-exponent RSA
  with related messages*, EUROCRYPT 1996 author PDF at
  `https://users.ece.cmu.edu/~reiter/papers/1996/Eurocrypt.pdf`.
- **Pinned challenge example:** No external mapping is asserted in v1. Treat the card as
  blocked until exact challenge source and relation coefficients are pinned.
