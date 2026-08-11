UNIT_PRICE = 1250
MAX_QUANTITY = 100


def total(quantity):
    if quantity < 1 or quantity > MAX_QUANTITY:
        raise ValueError(quantity)
    return UNIT_PRICE * quantity
