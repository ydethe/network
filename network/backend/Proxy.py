from umbral import pre, VerifiedKeyFrag, VerifiedCapsuleFrag, Capsule


class Proxy(object):
    """Proxy that can reencrypt a message sent by Alice to Bob,
    never seeing it clear

    """

    def __init__(self) -> None:
        pass

    def reencrypt(self, capsule: Capsule, kfrag: VerifiedKeyFrag) -> VerifiedCapsuleFrag:
        """Reencrypt on VerifiedKeyFrag to one VerifiedCapsuleFrag

        Args:
            capsule: The capsule returnd by the User.encrypt method
            kfrag: The VerifiedKeyFrag to reencrypt

        Returns:
            The VerifiedCapsuleFrag

        """
        cfrag = pre.reencrypt(capsule=capsule, kfrag=kfrag)
        return cfrag
