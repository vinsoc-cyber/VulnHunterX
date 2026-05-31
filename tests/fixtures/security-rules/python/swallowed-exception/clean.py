def check(signer, sig, data):
    try:
        signer.verify(sig, data)
        return True
    except Exception:
        return False
