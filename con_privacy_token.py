"""
CONFIDENTIAL-COMMITMENT TOKEN

Balances are stored as multiplicative commitments C.
On-chain enforces ONLY algebraic conservation:
  - C_sender_old == C_sender_new * C_amount
  - C_receiver_new == C_receiver_old * C_amount

Public total_supply is maintained.
"""

# -----------------------------------------------------------------------------
# Parameters & Helpers
# -----------------------------------------------------------------------------

p = 2**255 - 19  # modulus for modular arithmetic (big prime)

def domain_hash(*parts):
    s = "|".join(str(x) for x in parts)
    return hashlib.sha3("XCTOK:v2|" + s)

def map_to_base(tag: str):
    # Derive a base in [2, p-2] from sha3(tag)
    return int(hashlib.sha3("XCTOK:gen:" + tag)[:32], 16) % (p - 3) + 2

def mod_exp(base: int, exponent: int, modulus: int):
    if exponent == 0:
        return 1
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def mod_inverse(x: int, modulus: int):
    # Fermat since p is prime and x assumed != 0 mod p
    return mod_exp(x, modulus - 2, modulus)

def create_commitment(value, blinding: int):
    # Pedersen-like form over integers mod p (informational only)
    # value can be float; we hash (value) into an exponent to keep types simple on-chain
    # This keeps the contract agnostic to float representation.
    val_hash = int(hashlib.sha3("VAL|" + str(value))[:32], 16) % (p - 1)
    return (mod_exp(g, val_hash, p) * mod_exp(h, blinding % (p - 1), p)) % p

def verify_commitment_addition(old_commitment: int, amount_commitment: int, new_commitment: int):
    expected_new = (old_commitment * amount_commitment) % p
    return new_commitment == expected_new

def verify_commitment_subtraction(old_commitment: int, new_commitment: int, amount_commitment: int):
    expected_old = (new_commitment * amount_commitment) % p
    return old_commitment == expected_old

# Generators (informational; no subgroup checks here in Option B)
g = map_to_base("g")
h = map_to_base("h")
assert g != h and g not in (1, p-1) and h not in (1, p-1), "Bad generators"

ZERO_COMMITMENT = 1  # multiplicative identity

# -----------------------------------------------------------------------------
# State
# -----------------------------------------------------------------------------

# address -> {'commitment': int, 'last_updated': int, 'updates': int}
balance_commitments = Hash()

# (owner, spender) -> {'commitment': int, 'approved_at': int}
approvals = Hash()

# contract metadata / config
metadata = Hash()
# address -> int (monotonic)
nonces = Hash()

# counter for events
next_tx_id = Variable()

# Events
ConfidentialTransferEvent = LogEvent('ConfidentialTransfer', {
    'from': {'type': str, 'idx': True},
    'to': {'type': str, 'idx': True},
    'amount_commitment': {'type': str},
    'tx_id': {'type': int, 'idx': True}
})

ConfidentialApproveEvent = LogEvent('ConfidentialApprove', {
    'owner': {'type': str, 'idx': True},
    'spender': {'type': str, 'idx': True},
    'allowance_commitment': {'type': str},
    'tx_id': {'type': int, 'idx': True}
})

MintCommitmentEvent = LogEvent('MintCommitment', {
    'to': {'type': str, 'idx': True},
    'amount': {'type': float},
    'amount_commitment': {'type': str},
    'tx_id': {'type': int, 'idx': True}
})

BurnCommitmentEvent = LogEvent('BurnCommitment', {
    'from': {'type': str, 'idx': True},
    'amount': {'type': float},
    'amount_commitment': {'type': str},
    'tx_id': {'type': int, 'idx': True}
})

# -----------------------------------------------------------------------------
# Construction
# -----------------------------------------------------------------------------

@construct
def seed():
    metadata['name'] = "Confidential Commitment Token"
    metadata['symbol'] = "CCT"
    metadata['operator'] = ctx.caller

    # Public supply
    metadata['total_supply'] = 0.0

    # Supply commitment tracks product of all commitments (algebraic conservation)
    metadata['supply_commitment'] = ZERO_COMMITMENT

    next_tx_id.set(1)

# -----------------------------------------------------------------------------
# Views
# -----------------------------------------------------------------------------

@export
def get_metadata():
    return {
        'name': metadata['name'],
        'symbol': metadata['symbol'],
        'operator': metadata['operator'],
        'total_supply': metadata['total_supply'],
        'supply_commitment': metadata['supply_commitment']
    }

@export
def change_metadata(key: str, value: Any):
    assert ctx.caller == metadata['operator'], 'Only operator can set metadata'
    metadata[key] = value

@export
def get_balance_commitment(address: str):
    data = balance_commitments[address]
    if data is None:
        return {
            'exists': False,
            'commitment': ZERO_COMMITMENT,
            'last_updated': 0,
            'updates': 0
        }
    return {
        'exists': True,
        'commitment': data['commitment'],
        'last_updated': data['last_updated'],
        'updates': data['updates']
    }

@export
def get_confidential_approval(owner: str, spender: str):
    data = approvals[owner, spender]
    if data is None:
        return {
            'exists': False,
            'owner': owner,
            'spender': spender,
            'commitment': ZERO_COMMITMENT,
            'approved_at': 0
        }
    return {
        'exists': True,
        'owner': owner,
        'spender': spender,
        'commitment': data['commitment'],
        'approved_at': data['approved_at']
    }

@export
def get_nonce(address: str):
    n = nonces[address]
    return n if n is not None else 0

# -----------------------------------------------------------------------------
# Core: Commitment-only transfers (no ZK)
# -----------------------------------------------------------------------------

def bump_nonce(addr: str, provided: int):
    current = nonces[addr]
    if current is None:
        current = 0
    assert provided == current + 1, 'Bad nonce'
    nonces[addr] = provided

def next_tx():
    tid = next_tx_id.get()
    next_tx_id.set(tid + 1)
    return tid

@export
def confidential_transfer(to: str,
                          amount_commitment: int,
                          new_sender_commitment: int,
                          new_receiver_commitment: int,
                          nonce: int):
    assert to != ctx.caller, 'Cannot transfer to self'

    # replay protection
    bump_nonce(ctx.caller, nonce)

    sender_data = balance_commitments[ctx.caller]
    receiver_data = balance_commitments[to]

    current_sender_commitment = sender_data['commitment'] if sender_data else ZERO_COMMITMENT
    current_receiver_commitment = receiver_data['commitment'] if receiver_data else ZERO_COMMITMENT

    # Algebraic checks
    assert verify_commitment_subtraction(current_sender_commitment, new_sender_commitment, amount_commitment), 'Sender commitment mismatch'
    assert verify_commitment_addition(current_receiver_commitment, amount_commitment, new_receiver_commitment), 'Receiver commitment mismatch'

    # Write state
    balance_commitments[ctx.caller] = {
        'commitment': new_sender_commitment,
        'last_updated': block_num,
        'updates': (0 if sender_data is None else sender_data['updates']) + 1
    }

    balance_commitments[to] = {
        'commitment': new_receiver_commitment,
        'last_updated': block_num,
        'updates': (0 if receiver_data is None else receiver_data['updates']) + 1
    }

    # Emit event
    tx_id = next_tx()
    ConfidentialTransferEvent({
        'from': ctx.caller,
        'to': to,
        'amount_commitment': hex(amount_commitment),
        'tx_id': tx_id
    })

@export
def confidential_approve(spender: str, allowance_commitment: int, nonce: int):
    # replay protection
    bump_nonce(ctx.caller, nonce)

    approvals[ctx.caller, spender] = {
        'commitment': allowance_commitment,
        'approved_at': block_num
    }

    tx_id = next_tx()
    ConfidentialApproveEvent({
        'owner': ctx.caller,
        'spender': spender,
        'allowance_commitment': hex(allowance_commitment),
        'tx_id': tx_id
    })

@export
def confidential_transfer_from(owner: str,
                               to: str,
                               amount_commitment: int,
                               new_owner_commitment: int,
                               new_receiver_commitment: int,
                               new_allowance_commitment: int,
                               nonce: int):
    assert to != owner, 'Use confidential_transfer for self to self'

    # replay protection (spender)
    bump_nonce(ctx.caller, nonce)

    owner_data = balance_commitments[owner]
    assert owner_data is not None, 'Owner has no commitment'

    receiver_data = balance_commitments[to]
    current_owner_commitment = owner_data['commitment']
    current_receiver_commitment = receiver_data['commitment'] if receiver_data else ZERO_COMMITMENT

    approval = approvals[owner, ctx.caller]
    assert approval is not None, 'No approval for spender'
    current_allowance_commitment = approval['commitment']

    # Algebraic checks
    assert verify_commitment_subtraction(current_owner_commitment, new_owner_commitment, amount_commitment), 'Owner commitment mismatch'
    assert verify_commitment_addition(current_receiver_commitment, amount_commitment, new_receiver_commitment), 'Receiver commitment mismatch'
    assert verify_commitment_subtraction(current_allowance_commitment, new_allowance_commitment, amount_commitment), 'Allowance commitment mismatch'

    # Write state
    balance_commitments[owner] = {
        'commitment': new_owner_commitment,
        'last_updated': block_num,
        'updates': owner_data['updates'] + 1
    }

    balance_commitments[to] = {
        'commitment': new_receiver_commitment,
        'last_updated': block_num,
        'updates': (0 if receiver_data is None else receiver_data['updates']) + 1
    }

    approvals[owner, ctx.caller] = {
        'commitment': new_allowance_commitment,
        'approved_at': approval['approved_at']
    }

    tx_id = next_tx()
    ConfidentialTransferEvent({
        'from': owner,
        'to': to,
        'amount_commitment': hex(amount_commitment),
        'tx_id': tx_id
    })

# -----------------------------------------------------------------------------
# Mint / Burn (public supply; commitment algebra for balances)
# -----------------------------------------------------------------------------

@export
def mint(to: str,
         amount: float,
         amount_commitment: int,
         new_receiver_commitment: int,
         nonce: int):
    assert ctx.caller == metadata['operator'], 'Only operator can mint'

    bump_nonce(ctx.caller, nonce)

    receiver_data = balance_commitments[to]
    current_receiver_commitment = receiver_data['commitment'] if receiver_data else ZERO_COMMITMENT

    # Algebraic check: C_recv_new == C_recv_old * C_amount
    assert verify_commitment_addition(current_receiver_commitment, amount_commitment, new_receiver_commitment), 'Receiver commitment mismatch'

    # Update receiver
    balance_commitments[to] = {
        'commitment': new_receiver_commitment,
        'last_updated': block_num,
        'updates': (0 if receiver_data is None else receiver_data['updates']) + 1
    }

    # Update public supply and supply commitment
    metadata['total_supply'] = (metadata['total_supply'] or 0.0) + float(amount)
    supply_cmt = metadata['supply_commitment'] or ZERO_COMMITMENT
    metadata['supply_commitment'] = (supply_cmt * amount_commitment) % p

    tx_id = next_tx()
    MintCommitmentEvent({
        'to': to,
        'amount': float(amount),
        'amount_commitment': hex(amount_commitment),
        'tx_id': tx_id
    })

@export
def burn(from_address: str,
         amount: float,
         amount_commitment: int,
         new_from_commitment: int,
         nonce: int):
    # Allow owner to burn their own, or operator to force-burn (admin)
    assert ctx.caller == from_address or ctx.caller == metadata['operator'], 'Not authorized to burn'

    bump_nonce(ctx.caller, nonce)

    from_data = balance_commitments[from_address]
    assert from_data is not None, 'No commitment to burn from'

    current_from_commitment = from_data['commitment']

    # Algebraic check: C_from_old == C_from_new * C_amount
    assert verify_commitment_subtraction(current_from_commitment, new_from_commitment, amount_commitment), 'From commitment mismatch'

    # Update holder
    balance_commitments[from_address] = {
        'commitment': new_from_commitment,
        'last_updated': block_num,
        'updates': from_data['updates'] + 1
    }

    # Update public supply and supply commitment (multiply by inverse of C_amount)
    metadata['total_supply'] = (metadata['total_supply'] or 0.0) - float(amount)
    supply_cmt = metadata['supply_commitment'] or ZERO_COMMITMENT
    inv = mod_inverse(amount_commitment % p, p)
    metadata['supply_commitment'] = (supply_cmt * inv) % p

    tx_id = next_tx()
    BurnCommitmentEvent({
        'from': from_address,
        'amount': float(amount),
        'amount_commitment': hex(amount_commitment),
        'tx_id': tx_id
    })

# -----------------------------------------------------------------------------
# Invariants / Utilities
# -----------------------------------------------------------------------------

@export
def verify_supply_invariant():
    # Product of all account commitments should equal supply_commitment (if no rogue state)
    prod = 1
    count = 0
    items = balance_commitments.all()
    for v in items:
        if v and isinstance(v, dict):
            prod = (prod * int(v.get('commitment', 1))) % p
            count += 1
    expected = metadata['supply_commitment']
    return {
        'ok': prod == expected,
        'product': prod,
        'expected': expected,
        'accounts': count
    }
