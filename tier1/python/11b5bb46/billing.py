STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"


def charge(amount):
    return {"key": STRIPE_KEY, "amount": amount}
