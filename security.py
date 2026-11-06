import re
from decimal import Decimal, InvalidOperation


def validate_amount(value):
    try:
        amount = Decimal(str(value))

        if not amount.is_finite() or amount <= 0:
            return None

        if amount.as_tuple().exponent < -2:
            return None

        paise = amount * 100

        if paise != paise.to_integral_value():
            return None

        return int(paise)

    except (InvalidOperation, ValueError, TypeError):
        return None


def validate_transaction_id(transaction_id):
    if not isinstance(transaction_id, str):
        return False

    return bool(
        re.fullmatch(r"[A-Za-z0-9_-]{16,64}", transaction_id)
    )


def validate_pin(pin):
    return (
        isinstance(pin, str)
        and len(pin) == 4
        and pin.isascii()
        and pin.isdigit()
    )