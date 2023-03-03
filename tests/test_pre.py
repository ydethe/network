from umbral import pre

from network.User import User


alice = User("alice")
bob = User("bob")

original_text = b"Je suis un poney"
capsule, ciphertext = alice.encrypt(original_text)

kfrags = alice.generate_kfrags(bob.public_key, threshold=10, shares=20)

# Several Ursulas perform re-encryption, and Bob collects the resulting `cfrags`.
cfrags = list()  # Bob's cfrag collection
for kfrag in kfrags[:10]:
    cfrag = pre.reencrypt(capsule=capsule, kfrag=kfrag)
    cfrags.append(cfrag)  # Bob collects a cfrag

bob_cleartext = bob.decrypt_reencrypted(alice.public_key, cfrags, capsule, ciphertext)
assert bob_cleartext == original_text
