from umbral import PublicKey

from network.User import User
from network.Proxy import Proxy


def test_legacy():
    alice = User("alice")
    bob = User("bob")
    ursulas = [Proxy() for _ in range(10)]
    assert alice.name == "alice"
    assert isinstance(alice.public_key, PublicKey)
    assert isinstance(alice.verifying_key, PublicKey)

    # ===================================
    # Alice prepares her message to send
    # ===================================
    original_text = b"Je suis un poney"
    capsule, ciphertext = alice.encrypt(original_text)
    alice_cleartext = alice.decrypt(capsule, ciphertext)
    assert alice_cleartext == original_text


def test_pre():
    alice = User("alice")
    bob = User("bob")
    ursulas = [Proxy() for _ in range(10)]

    # ===================================
    # Alice prepares her message to send
    # ===================================
    original_text = b"Je suis un poney"
    capsule, ciphertext = alice.encrypt(original_text)
    kfrags = alice.generate_kfrags(bob, threshold=10, shares=10)

    # ===================================
    # The proxies perform reencryption
    # ===================================
    # Several Ursulas perform re-encryption, and Bob collects the resulting `cfrags`.
    cfrags = list()  # Bob's cfrag collection
    for u, kfrag in zip(ursulas, kfrags):
        cfrag = u.reencrypt(capsule, kfrag)
        cfrags.append(cfrag)  # Bob collects a cfrag

    # =====================================
    # Bob decrypts the reencrypted message
    # =====================================
    bob_cleartext = bob.decrypt_reencrypted(alice, cfrags, capsule, ciphertext)
    assert bob_cleartext == original_text
