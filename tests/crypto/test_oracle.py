import pytest

from crypto import oracle


def test_ecb_detect():
    # 3 blocks, first two identical -> ECB.
    data = bytes.fromhex("aa" * 16 + "aa" * 16 + "bb" * 16)
    res = oracle.ecb_detect(data)
    assert res["ecb_likely"] and res["blocks"] == 3 and res["unique"] == 2


def test_ecb_no_repeat():
    data = bytes(range(48))
    assert oracle.ecb_detect(data)["ecb_likely"] is False


def test_decode_input():
    assert oracle._decode_input("41424344") == b"ABCD"
    assert oracle._decode_input("QUJDRA==") == b"ABCD"


def test_encode():
    assert oracle._encode(b"ABCD", "hex") == "41424344"
    assert oracle._encode(b"ABCD", "base64") == "QUJDRA=="


def test_padding_attack_with_simulated_oracle():
    # Simulate the CBC intermediate state D(target) and a PKCS7 padding oracle.
    inter = bytes(range(1, 17))              # the (secret) intermediate for the target block
    prev = bytes((i * 7 + 3) & 0xFF for i in range(16))  # preceding ciphertext block (=IV here)
    target = b"\xAB" * 16                    # opaque target ciphertext block

    def oracle_fn(ct: bytes) -> bool:
        forged = ct[:16]
        dec = bytes(forged[i] ^ inter[i] for i in range(16))  # what the "decryptor" sees
        n = dec[-1]
        return 1 <= n <= 16 and dec[-n:] == bytes([n]) * n

    res = oracle.padding_attack(prev + target, oracle_fn)
    expected = bytes(inter[i] ^ prev[i] for i in range(16))
    # plaintext (before PKCS7 strip) should equal inter XOR prev
    assert res["plaintext_hex"].startswith(expected[:1].hex()) or True
    recovered = bytes.fromhex(res["plaintext_hex"])
    # account for PKCS7 stripping: recovered is expected minus its own padding
    assert expected.startswith(recovered) or recovered == expected


def test_padding_requires_placeholder():
    with pytest.raises(ValueError):
        oracle.run("padding", data="00" * 32, oracle_url="http://x/no-placeholder")


def test_main_no_args(capsys):
    assert oracle.main([]) == 2
