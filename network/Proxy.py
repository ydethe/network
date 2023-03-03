from umbral import pre, VerifiedKeyFrag, VerifiedCapsuleFrag, Capsule


class Proxy(object):
    def __init__(self) -> None:
        pass

    def reencrypt(self, capsule: Capsule, kfrag: VerifiedKeyFrag) -> VerifiedCapsuleFrag:
        cfrag = pre.reencrypt(capsule=capsule, kfrag=kfrag)
        return cfrag
