from __future__ import annotations
from abc import ABC, abstractmethod

class SigmaParticipant(ABC):
    @abstractmethod
    def public_info():
        raise NotImplementedError

class SigmaProver(SigmaParticipant):
    @abstractmethod
    def commitment(self, transcript):
        raise NotImplementedError

    @abstractmethod
    def response(self, transcript):
        raise NotImplementedError


class SigmaVerifier(SigmaParticipant):
    @abstractmethod
    def challenge(self, transcript):
        raise NotImplementedError

    @abstractmethod
    def verify(self, transcript) -> bool:
        raise NotImplementedError


def sigma_protocol(prover: SigmaProver, verifier: SigmaVerifier) -> (list, bool):
    transcript = [prover.public_info(), verifier.public_info()]
    transcript.append(prover.commitment(transcript))
    transcript.append(verifier.challenge(transcript))
    transcript.append(prover.response(transcript))
    return transcript, verifier.verify(transcript)


def fiat_shamir_sign(prover: SigmaProver, msg: bytes | None, hash_function) -> tuple:
    pub = prover.public_info()
    transcript = [prover.public_info(), None]

    commit = prover.commitment(transcript)
    transcript.append(commit)
    transcript.append(hash_function(pub, msg))

    y = prover.response(transcript)
    return commit, y


def fiat_shamir_verify(verifier: SigmaVerifier, msg: bytes | None, sig, public_info, hash_function) -> bool:
    pk = public_info
    commit, y = sig

    x = hash_function(pk, msg)
    transcript = [pk, None, commit, x, y]
    return verifier.verify(transcript)
