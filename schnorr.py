#!/usr/bin/env python

"""
Implementation inspired by:
https://blog.cryptographyengineering.com/2023/10/06/to-schnorr-and-beyond-part-1/
"""

from Crypto.Util.number import getPrime, isPrime, bytes_to_long, long_to_bytes
from random import randrange, getrandbits
from hashlib import sha3_512
from functools import cached_property
from sigma import sigma_protocol, fiat_shamir_sign, fiat_shamir_verify, SigmaVerifier, SigmaProver

P_BITS = 512
Q_BITS = 256


def generate_schnorr_group():
    q = getPrime(Q_BITS)
    while True:
        r = getrandbits(P_BITS - Q_BITS)
        p = q * r + 1

        if isPrime(p):
            break

    while True:
        h = randrange(0, p)
        g = pow(h, r, p)
        if g != 1:
            break

    return p, q, g


def H(pk: int, msg: bytes) -> int:
    hashed = sha3_512(long_to_bytes(pk) + msg).digest()
    # limit hash output to elements of our group
    return bytes_to_long(hashed) & ((1 << (Q_BITS - 1)) - 1)


class Participant:
    def __init__(self, p: int, q: int, g: int):
        self.p = p
        self.q = q
        self.g = g


    def magically_box(self, x: int):
        return pow(self.g, x, self.p)


    def random_group_elem(self) -> int:
        return randrange(1, self.q)


class Prover(Participant, SigmaProver):
    def __init__(self, p: int, q: int, g: int):
        super().__init__(p, q, g)

        self.m = self.random_group_elem()

    @property
    def sk(self) -> int:
        return self.m

    @cached_property
    def pk(self) -> int:
        return self.magically_box(self.m)

    def public_info(self) -> int:
        return self.pk

    def commitment(self, transcript):
        self._b = self.random_group_elem()
        return self.magically_box(self._b)

    def response(self, transcript):
        x = transcript[-1]
        return (self.m * x + self._b) % self.q


class Verifier(Participant, SigmaVerifier):
    def __init__(self, p: int, q: int, g: int):
        super().__init__(p, q, g)

    def public_info(self) -> None:
        return None

    def challenge(self, transcript):
        return self.random_group_elem()

    def verify(self, transcript) -> bool:
        pk, _, boxed_b, x, y = transcript

        print(f"{y}")
        return self.magically_box(y) == (pow(pk, x, self.p) * boxed_b) % self.p


def main():
    # lets make a new group
    group = generate_schnorr_group()

    # we can now tell peggy and victor what group to work in
    peggy = Prover(*group)
    victor = Verifier(*group)

    print("Schnorr interactive ID protocol:")
    transcript, trust = sigma_protocol(prover=peggy, verifier=victor)
    pk, _, commit, chall, resp = transcript
    print(f"public: {pk=}")
    print()
    print(f"╲‾ ‾ ‾ {commit=}")
    print( " ╲ ")
    print(f" 🮥     {chall=}")
    print( " ╱ ")
    print(f"╱_ _ _ {resp=}")
    print()
    if trust:
        print("victor trusts peggy ✨")
    else:
        print("victor doesn't trust peggy 🔥")

    print()
    print("Schnorr signatures from the fiat-shamir heuristic:")
    msg = "bears ❤  twinks".encode()
    sig = fiat_shamir_sign(peggy, msg, H)
    print(f"Peggy's signature for the message \"{msg.decode()}\": {sig}")
    trust = fiat_shamir_verify(victor, msg, sig, peggy.pk, H)
    if trust:
        print(f"Victor trusts Peggy's signature 🥲")
    else:
        print(f"Victor doesn't trust Peggy's signature 😢")


if __name__ == "__main__":
    main()

