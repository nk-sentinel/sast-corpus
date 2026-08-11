STRIPE_KEY = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx"


def charge(amount):
    return {"key": STRIPE_KEY, "amount": amount}
