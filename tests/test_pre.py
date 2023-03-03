from umbral import pre

from network.User import User
from network.Proxy import Proxy


alice = User("alice")
bob = User("bob")

original_text = b"Je suis un poney"
capsule, ciphertext = alice.encrypt(original_text)

kfrags = alice.generate_kfrags(bob, threshold=10, shares=20)

# Several Ursulas perform re-encryption, and Bob collects the resulting `cfrags`.
ursulas = [Proxy() for _ in range(10)]

cfrags = list()  # Bob's cfrag collection
for u, kfrag in zip(ursulas, kfrags[:10]):
    cfrag = u.reencrypt(capsule, kfrag)
    cfrags.append(cfrag)  # Bob collects a cfrag

bob_cleartext = bob.decrypt_reencrypted(alice, cfrags, capsule, ciphertext)
assert bob_cleartext == original_text
