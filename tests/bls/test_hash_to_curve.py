"""Tests T9 (offline) and T10 (live), docs/design/001-bls-primitives.md §11.

Vectors below are transcribed verbatim from RFC 9380 Appendix K.1
(`expand_message_xmd(SHA-256)`) and Appendix J.10.1
(`BLS12381G2_XMD:SHA-256_SSWU_RO_`) -- the RFC's own published test vectors,
not derived from py_ecc or from this repo's own implementation. This is
what makes T9/T10 "exact" per the design doc rather than merely
self-consistent.
"""

from __future__ import annotations

import pytest

from . import reference as ref

DST_XMD = b"QUUX-V01-CS02-with-expander-SHA256-128"
DST_H2C = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"

# ---------------------------------------------------------------------------
# T9 -- RFC 9380 Appendix K.1, expand_message_xmd(SHA-256), exact.
# ---------------------------------------------------------------------------

XMD_VECTORS = [
    # (msg, len_in_bytes, uniform_bytes hex)
    (b"", 0x20, "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"),
    (b"abc", 0x20, "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"),
    (
        b"abcdef0123456789",
        0x20,
        "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
    ),
    (b"", 0x80, (
        "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d1215877"
        "13a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658"
        "e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4"
        "286b004ceb5ee6b9a7fa5b646c993f0ced"
    )),
    (b"abc", 0x80, (
        "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163"
        "d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7"
        "ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec"
        "65e8afc50303a22c0f99b0509b4c895f40"
    )),
    (b"abcdef0123456789", 0x80, (
        "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635c"
        "d1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef"
        "653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453"
        "b2c9d9eb20c7e3f6edc5a60629178d9478df"
    )),
]


@pytest.mark.parametrize("msg,len_in_bytes,expected_hex", XMD_VECTORS)
def test_t9_expand_message_xmd_rfc9380_appendix_k1(msg, len_in_bytes, expected_hex):
    got = ref.expand_message_xmd_sha256(msg, DST_XMD, len_in_bytes)
    assert got.hex() == expected_hex


# ---------------------------------------------------------------------------
# T10 -- RFC 9380 Appendix J.10.1, BLS12381G2_XMD:SHA-256_SSWU_RO_, live
# (needs the real ec_map_to / ec_add G2 opcodes).
# ---------------------------------------------------------------------------

# Each entry: msg, P.x = (c0, c1), P.y = (c0, c1), all as hex strings (48 B
# each), transcribed from RFC 9380 §J.10.1.
H2C_VECTORS = [
    (
        b"",
        (
            "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
            "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
        ),
        (
            "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
            "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
        ),
    ),
    (
        b"abc",
        (
            "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
            "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
        ),
        (
            "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
            "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
        ),
    ),
    (
        b"abcdef0123456789",
        (
            "121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
            "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c",
        ),
        (
            "05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8",
            "0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be",
        ),
    ),
    (
        # RFC 9380 names this vector "q128": the literal msg is "q128_"
        # followed by exactly 128 repetitions of "q" (verified against
        # Appendix K.1's expand_message_xmd uniform_bytes for this exact
        # msg with DST "...expander-SHA256-128" -- a prior transcription
        # of this vector was short by 22 "q"s and silently produced a
        # self-consistent-but-wrong result; do not hand-transcribe this
        # again, construct it).
        b"q128_" + b"q" * 128,
        (
            "19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da",
            "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91",
        ),
        (
            "14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192",
            "09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662",
        ),
    ),
    (
        # RFC 9380 names this vector "a512": literal msg is "a512_" followed
        # by exactly 512 repetitions of "a" (same transcription-length trap
        # as "q128" above -- verified against Appendix K.1's uniform_bytes
        # for this exact msg). A prior transcription was short by 45 "a"s.
        b"a512_" + b"a" * 512,
        (
            "01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
            "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569",
        ),
        (
            "0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e",
            "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52",
        ),
    ),
]


H2C_VECTOR_IDS = ["empty", "abc", "abcdef0123456789", "q128", "a512"]


@pytest.mark.parametrize("msg,px,py", H2C_VECTORS, ids=H2C_VECTOR_IDS)
def test_t10_live_hash_to_g2_rfc9380_appendix_j10_1(live_harness, msg, px, py):
    expected = bytes.fromhex(px[0] + px[1] + py[0] + py[1])
    r = live_harness.call("hash_to_g2", msg, DST_H2C)
    assert r.ok, r.failure
    got = r.return_value[2:]  # strip byte[] length prefix
    assert len(got) == ref.G2_BYTES
    assert got == expected
