SIGNING_KEY = "hunter2-Zx9Qv7Lm3Rt8Wn2Kd6Yp4Bs1Hf5Jg0Ac"


def sign(payload):
    return payload + SIGNING_KEY
