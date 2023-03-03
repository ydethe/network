from umbral import pre

from kfrags import kfrags
from encryption import capsule


# Several Ursulas perform re-encryption, and Bob collects the resulting `cfrags`.
cfrags = list()  # Bob's cfrag collection
for kfrag in kfrags[:10]:
    cfrag = pre.reencrypt(capsule=capsule, kfrag=kfrag)
    cfrags.append(cfrag)  # Bob collects a cfrag
