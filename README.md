# Confidential Commitment Token

## Overview
This repository prototypes a confidential commitment token for the Xian network. Rather than publishing balances, every account, allowance, and supply figure is stored as a multiplicative commitment inside the smart contract (`con_privacy_token.py`). Clients exchange blinded commitments off-chain and submit the resulting products to the chain, preserving numeric privacy while keeping the public address graph intact. A companion helper module (`client_helper.py`) mirrors the contract math so wallets and operators can mint, transfer, burn, and track balances without leaking blindings.

## How the Token Works
- **Pedersen-style commitments:** Balances are encoded as `C = g^val_hash * h^blinding mod p`, where `val_hash` deterministically hashes the textual value and the blinding is user supplied. Transfers and burns only pass new commitments; on-chain functions verify algebraic relations instead of raw amounts.
- **Decimals on supply:** The contract now tracks `total_supply` with `decimal.Decimal` values, avoiding float drift across mint and burn operations while events still emit user-friendly floats.
- **Nonce-based replay defence:** Each caller maintains a monotonic nonce stored in the contract. Wallets must advance the nonce per interaction and are expected to guard it client-side.
- **Operator controls:** An operator set during deployment can mint new commitments and optionally force-burn accounts. The helper library exposes builders for both flows and a lightweight account tracker.

## Project Layout
- `con_privacy_token.py` — Xian contract implementation with commitment helpers, transfer logic, mint/burn routines, and a supply invariant check.
- `client_helper.py` — Off-chain toolkit for generating commitments, computing new state after operations, and handling local account mirrors.
- `tests/` — Pytest suite that deploys the contract with `ContractingClient`, exercises every execution path, and cross-checks helper utilities against on-chain algebra.
- `AGENTS.md` — Contributor guidelines.

## Running the Test Suite
Tests execute the contract against the real Xian execution engine (`xian-contracting`) in a local virtual environment. Recommended workflow:

```bash
python3.11 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest
```

Run subsets as needed:

```bash
pytest tests/test_contract.py -k transfer
pytest tests/test_client_helper.py
```

Each test deploys a fresh contract instance via `ContractingClient`, patches `hashlib.sha3` to match on-chain semantics, and steps block numbers manually through the executor environment.

## Example Workflow
1. Use `client_helper.build_mint` to create the commitment args for a mint, then call `con_privacy_token.mint` as the operator to credit an address while updating the public supply.
2. Wallets call `client_helper.build_confidential_transfer` or `build_confidential_transfer_from` to prepare new commitments for transfers and allowance spends. The contract validates them against existing state and bumps nonces for replay protection.
3. Periodically call `verify_supply_invariant` to confirm the product of account commitments still matches `metadata['supply_commitment']`; the test suite covers both the happy path and tampering detection.
