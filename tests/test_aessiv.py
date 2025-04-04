import random

import pytest

from wolfcrypt.ciphers import AesSiv


def test_aessiv_encrypt_decrypt():
    key = random.randbytes(32)
    aessiv = AesSiv(key)
    associated_data = random.randbytes(16)
    nonce = random.randbytes(12)
    plaintext = random.randbytes(16)
    siv, ciphertext = aessiv.encrypt(associated_data, nonce, plaintext)
    assert aessiv.decrypt(associated_data, nonce, siv, ciphertext) == plaintext

#
# Test vectors copied from RFC-5297.
#
TEST_VECTOR_KEY_RFC5297 = bytes.fromhex("""
7f7e7d7c 7b7a7978 77767574 73727170
40414243 44454647 48494a4b 4c4d4e4f
""")
TEST_VECTOR_ASSOCIATED_DATA_1_RFC5297 = bytes.fromhex("""
00112233 44556677 8899aabb ccddeeff
deaddada deaddada ffeeddcc bbaa9988
77665544 33221100
""")
TEST_VECTOR_ASSOCIATED_DATA_2_RFC5297 = bytes.fromhex("""
10203040 50607080 90a0
""")
TEST_VECTOR_NONCE_RFC5297 = bytes.fromhex("""
09f91102 9d74e35b d84156c5 635688c0
""")
TEST_VECTOR_PLAINTEXT_RFC5297 = bytes.fromhex("""
74686973 20697320 736f6d65 20706c61
696e7465 78742074 6f20656e 63727970
74207573 696e6720 5349562d 414553
""")
TEST_VECTOR_SIV_RFC5297 = bytes.fromhex("""
7bdb6e3b 432667eb 06f4d14b ff2fbd0f
""")
TEST_VECTOR_CIPHERTEXT_RFC5297 = bytes.fromhex("""
cb900f2f ddbe4043 26601965 c889bf17
dba77ceb 094fa663 b7a3f748 ba8af829
ea64ad54 4a272e9c 485b62a3 fd5c0d
""")


@pytest.mark.skip(reason="Associated data in test vector consists of multiple blocks which is unsupported")
def test_aessiv_encrypt_kat_rfc5297():
    """
    Known-answer test using test vectors from RFC-5297.
    """
    aessiv = AesSiv(TEST_VECTOR_KEY_RFC5297)
    # This is probably not the correct way of handling the associated data.
    # The function wc_AesSivEncrypt_ex supports this but it is currently not exposed.
    associated_data = TEST_VECTOR_ASSOCIATED_DATA_1_RFC5297 + TEST_VECTOR_ASSOCIATED_DATA_2_RFC5297
    siv, ciphertext = aessiv.encrypt(associated_data, TEST_VECTOR_NONCE_RFC5297, TEST_VECTOR_PLAINTEXT_RFC5297)
    assert siv == TEST_VECTOR_SIV_RFC5297
    assert ciphertext == TEST_VECTOR_CIPHERTEXT_RFC5297

@pytest.mark.skip(reason="Associated data in test vector consists of multiple blocks which is unsupported")
def test_aessiv_decrypt_kat_rfc5297():
    """
    Known-answer test using test vectors from RFC-5297.
    """
    aessiv = AesSiv(TEST_VECTOR_KEY_RFC5297)
    # This is probably not the correct way of handling the associated data.
    # The function wc_AesSivEncrypt_ex supports this but it is currently not exposed.
    associated_data = TEST_VECTOR_ASSOCIATED_DATA_1_RFC5297 + TEST_VECTOR_ASSOCIATED_DATA_2_RFC5297
    plaintext = aessiv.decrypt(associated_data, TEST_VECTOR_NONCE_RFC5297, TEST_VECTOR_SIV_RFC5297, TEST_VECTOR_CIPHERTEXT_RFC5297)
    assert plaintext == TEST_VECTOR_PLAINTEXT_RFC5297


#
# Test vectors copied from OpenSSL library file evpciph_aes_siv.txt..
#
TEST_VECTOR_KEY_OPENSSL = bytes.fromhex("""
fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
""")
TEST_VECTOR_ASSOCIATED_DATA_OPENSSL = bytes.fromhex("""
101112131415161718191a1b1c1d1e1f2021222324252627
""")
TEST_VECTOR_NONCE_OPENSSL = b""
TEST_VECTOR_PLAINTEXT_OPENSSL = bytes.fromhex("""
112233445566778899aabbccddee
""")
TEST_VECTOR_SIV_OPENSSL = bytes.fromhex("""
85632d07c6e8f37f950acd320a2ecc93
""")
TEST_VECTOR_CIPHERTEXT_OPENSSL = bytes.fromhex("""
40c02b9690c4dc04daef7f6afe5c
""")


def test_aessiv_encrypt_kat_openssl():
    """
    Known-answer test using test vectors from OpenSSL.
    """
    aessiv = AesSiv(TEST_VECTOR_KEY_OPENSSL)
    siv, ciphertext = aessiv.encrypt(TEST_VECTOR_ASSOCIATED_DATA_OPENSSL, TEST_VECTOR_NONCE_OPENSSL, TEST_VECTOR_PLAINTEXT_OPENSSL)
    assert siv == TEST_VECTOR_SIV_OPENSSL
    assert ciphertext == TEST_VECTOR_CIPHERTEXT_OPENSSL

def test_aessiv_decrypt_kat_openssl():
    """
    Known-answer test using test vectors from OpenSSL.
    """
    aessiv = AesSiv(TEST_VECTOR_KEY_OPENSSL)
    plaintext = aessiv.decrypt(TEST_VECTOR_ASSOCIATED_DATA_OPENSSL, TEST_VECTOR_NONCE_OPENSSL, TEST_VECTOR_SIV_OPENSSL, TEST_VECTOR_CIPHERTEXT_OPENSSL)
    assert plaintext == TEST_VECTOR_PLAINTEXT_OPENSSL
