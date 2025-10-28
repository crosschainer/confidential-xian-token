
import secrets

# ---- Chain-constant parameters & helpers (mirror contract) ----

p = 2**255 - 19

def sha3_hex(s: str) -> str:
    # Matches Xian env semantics
    import hashlib
    return hashlib.sha3(s)

def map_to_base(tag: str) -> int:
    return int(sha3_hex("XCTOK:gen:" + tag)[:32], 16) % (p - 3) + 2

g = map_to_base("g")
h = map_to_base("h")

ZERO_COMMITMENT = 1

def mod_exp(base: int, exponent: int, modulus: int) -> int:
    if exponent == 0:
        return 1
    result = 1
    base = base % modulus
    e = exponent
    while e > 0:
        if e & 1:
            result = (result * base) % modulus
        e >>= 1
        base = (base * base) % modulus
    return result

def mod_inverse(x: int, modulus: int = p) -> int:
    return mod_exp(x % modulus, modulus - 2, modulus)

def value_to_exponent(value) -> int:
    # Keep float-safe & deterministic: hash textual form exactly like on-chain helper does
    return int(sha3_hex("VAL|" + str(value))[:32], 16) % (p - 1)

def create_commitment(value, blinding: int) -> int:
    # Mirrors on-chain create_commitment
    vexp = value_to_exponent(value)
    return (mod_exp(g, vexp, p) * mod_exp(h, blinding % (p - 1), p)) % p

def random_blinding() -> int:
    return secrets.randbelow(p - 1)

# ---- High-level builders -----------------------------------------------------

def build_confidential_transfer(sender_commitment: int,
                                receiver_commitment: int,
                                amount: float,
                                amount_blinding: int = None,
                                next_nonce: int = 1):
    """
    Returns args for contract.confidential_transfer():
        (to, amount_commitment, new_sender_commitment, new_receiver_commitment, nonce)
    You still supply `to` address when calling the chain method.
    """
    if amount_blinding is None:
        amount_blinding = random_blinding()

    amount_commitment = create_commitment(amount, amount_blinding)

    if sender_commitment is None or sender_commitment == 0:
        sender_commitment = ZERO_COMMITMENT
    if receiver_commitment is None or receiver_commitment == 0:
        receiver_commitment = ZERO_COMMITMENT

    inv_amt = mod_inverse(amount_commitment)
    new_sender_commitment = (sender_commitment * inv_amt) % p
    new_receiver_commitment = (receiver_commitment * amount_commitment) % p

    return {
        'amount_commitment': amount_commitment,
        'new_sender_commitment': new_sender_commitment,
        'new_receiver_commitment': new_receiver_commitment,
        'nonce': next_nonce
    }

def build_confidential_approve(current_allowance_commitment: int,
                               allowance_amount: float,
                               allowance_blinding: int = None,
                               next_nonce: int = 1):
    """
    Returns args for contract.confidential_approve():
        (spender, allowance_commitment, nonce)
    If you want to replace an existing allowance, just pass the new commitment.
    """
    if allowance_blinding is None:
        allowance_blinding = random_blinding()

    allowance_commitment = create_commitment(allowance_amount, allowance_blinding)
    # Note: contract sets approvals[(owner,spender)] = allowance_commitment (replace)
    return {
        'allowance_commitment': allowance_commitment,
        'nonce': next_nonce
    }

def build_confidential_transfer_from(owner_commitment: int,
                                     receiver_commitment: int,
                                     allowance_commitment: int,
                                     amount: float,
                                     amount_blinding: int = None,
                                     next_nonce: int = 1):
    """
    Returns args for contract.confidential_transfer_from():
        (owner, to, amount_commitment, new_owner_commitment, new_receiver_commitment, new_allowance_commitment, nonce)
    You still supply (owner, to) when calling the chain method.
    """
    if amount_blinding is None:
        amount_blinding = random_blinding()

    amount_commitment = create_commitment(amount, amount_blinding)

    if owner_commitment is None or owner_commitment == 0:
        raise ValueError("Owner must have an existing commitment")
    if receiver_commitment is None or receiver_commitment == 0:
        receiver_commitment = ZERO_COMMITMENT
    if allowance_commitment is None or allowance_commitment == 0:
        raise ValueError("Spender must have an existing allowance commitment")

    inv_amt = mod_inverse(amount_commitment)
    new_owner_commitment = (owner_commitment * inv_amt) % p
    new_receiver_commitment = (receiver_commitment * amount_commitment) % p
    new_allowance_commitment = (allowance_commitment * inv_amt) % p

    return {
        'amount_commitment': amount_commitment,
        'new_owner_commitment': new_owner_commitment,
        'new_receiver_commitment': new_receiver_commitment,
        'new_allowance_commitment': new_allowance_commitment,
        'nonce': next_nonce
    }

def build_mint(receiver_commitment: int,
               amount: float,
               amount_blinding: int = None,
               next_nonce: int = 1):
    """
    Returns args for contract.mint():
        (to, amount, amount_commitment, new_receiver_commitment, nonce)
    Operator-only on-chain.
    """
    if amount_blinding is None:
        amount_blinding = random_blinding()

    amount_commitment = create_commitment(amount, amount_blinding)
    if receiver_commitment is None or receiver_commitment == 0:
        receiver_commitment = ZERO_COMMITMENT

    new_receiver_commitment = (receiver_commitment * amount_commitment) % p

    return {
        'amount': float(amount),
        'amount_commitment': amount_commitment,
        'new_receiver_commitment': new_receiver_commitment,
        'nonce': next_nonce
    }

def build_burn(from_commitment: int,
               amount: float,
               amount_blinding: int = None,
               next_nonce: int = 1):
    """
    Returns args for contract.burn():
        (from_address, amount, amount_commitment, new_from_commitment, nonce)
    Caller must be from_address or operator (on-chain).
    """
    if amount_blinding is None:
        amount_blinding = random_blinding()

    if from_commitment is None or from_commitment == 0:
        raise ValueError("Account must have an existing commitment")

    amount_commitment = create_commitment(amount, amount_blinding)
    inv_amt = mod_inverse(amount_commitment)
    new_from_commitment = (from_commitment * inv_amt) % p

    return {
        'amount': float(amount),
        'amount_commitment': amount_commitment,
        'new_from_commitment': new_from_commitment,
        'nonce': next_nonce
    }

# ---- Convenience: wallet-side state tracker (optional) ----------------------

class CommitmentAccount:
    """
    Optional local helper to track a user's commitment without storing blindings on-chain.
    You keep only the current commitment value here.
    """
    def __init__(self, commitment: int = ZERO_COMMITMENT):
        self.commitment = commitment or ZERO_COMMITMENT

    def apply_incoming(self, amount_commitment: int):
        self.commitment = (self.commitment * amount_commitment) % p
        return self.commitment

    def apply_outgoing(self, amount_commitment: int):
        self.commitment = (self.commitment * mod_inverse(amount_commitment)) % p
        return self.commitment
