"""Three log envelope shapes, one decoder (design doc §7.8, §18 item 18):

| Producer   | Envelope                                       | Total  |
|------------|-------------------------------------------------|-------:|
| M5 / M6    | 0x151f7c75 || len(2) || W(101) || C(248)        | 355 B  |
| M7         | 0x151f7c75 || len(2) || W(101) || R(240)        | 347 B  |
| M8 attest  | 0x151f7c75 || A(154)  (NO length field)         | 158 B  |

M8's is different because `TrustedRootAnchor` is a real `ARC4Contract`,
and Puya's auto-generated return log for a fixed-size
`arc4.StaticArray[Byte, 154]` carries no length prefix -- a real finding
(008's row) confirmed against a live algod probe before `handoff.py` was
written against it. Asserts length BEFORE slicing, always (§18 item 18) --
a client that assumes one envelope shape silently mis-slices the other two.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

ARC4_RETURN_PREFIX = bytes.fromhex("151f7c75")

W_LEN = 101


class Producer(Enum):
    M5_M6 = auto()  # W(101) + C(248), 355 B total, length-prefixed
    M7 = auto()  # W(101) + R(240), 347 B total, length-prefixed
    M8_ATTEST = auto()  # A(154), 158 B total, NO length field


_ENVELOPE_TOTAL_LEN = {
    Producer.M5_M6: 4 + 2 + 101 + 248,  # 355
    Producer.M7: 4 + 2 + 101 + 240,  # 347
    Producer.M8_ATTEST: 4 + 154,  # 158
}


@dataclass(frozen=True)
class DecodedLog:
    producer: Producer
    w: bytes | None  # 101 B walk state, absent for M8
    payload: bytes  # C(248) / R(240) / A(154), whichever this producer carries


def decode_log(log_bytes: bytes, producer: Producer) -> DecodedLog:
    """Asserts the exact expected length BEFORE slicing anything (§18 item
    18) -- the only way three real, different envelope shapes can share
    one decoder safely."""
    expected = _ENVELOPE_TOTAL_LEN[producer]
    assert len(log_bytes) == expected, (
        f"expected a {expected}-byte {producer.name} log envelope, got {len(log_bytes)}"
    )
    assert log_bytes[0:4] == ARC4_RETURN_PREFIX, "bad ARC4 return-log prefix"
    if producer is Producer.M8_ATTEST:
        return DecodedLog(producer=producer, w=None, payload=log_bytes[4:])
    # M5/M6/M7: 0x151f7c75 || <2-byte BE length> || W(101) || payload
    payload_len = int.from_bytes(log_bytes[4:6], "big")
    assert payload_len == expected - 6, f"declared payload length {payload_len} != {expected - 6}"
    w = log_bytes[6:6 + W_LEN]
    payload = log_bytes[6 + W_LEN:]
    return DecodedLog(producer=producer, w=w, payload=payload)
