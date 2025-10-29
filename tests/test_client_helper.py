import pytest


def test_create_commitment_is_deterministic(helper_module):
    c1 = helper_module.create_commitment(5.5, 123)
    c2 = helper_module.create_commitment(5.5, 123)
    assert c1 == c2


def test_build_confidential_transfer_consistency(helper_module):
    sender = helper_module.create_commitment(12, 555)
    receiver = helper_module.ZERO_COMMITMENT
    plan = helper_module.build_confidential_transfer(
        sender_commitment=sender,
        receiver_commitment=receiver,
        amount=3,
        amount_blinding=777,
        next_nonce=4,
    )

    reconstructed_sender = (
        plan["new_sender_commitment"] * plan["amount_commitment"]
    ) % helper_module.p
    reconstructed_receiver = (
        plan["new_receiver_commitment"] * helper_module.mod_inverse(plan["amount_commitment"])
    ) % helper_module.p
    assert reconstructed_sender == sender
    assert reconstructed_receiver == receiver
    assert plan["nonce"] == 4


def test_build_confidential_transfer_from_requires_existing(helper_module):
    with pytest.raises(ValueError):
        helper_module.build_confidential_transfer_from(
            owner_commitment=None,
            receiver_commitment=helper_module.ZERO_COMMITMENT,
            allowance_commitment=1,
            amount=1,
        )

    with pytest.raises(ValueError):
        helper_module.build_confidential_transfer_from(
            owner_commitment=1,
            receiver_commitment=helper_module.ZERO_COMMITMENT,
            allowance_commitment=None,
            amount=1,
        )


def test_build_confidential_transfer_from_updates_all(helper_module):
    owner = helper_module.create_commitment(9, 4321)
    receiver = helper_module.create_commitment(2, 9876)
    allowance = helper_module.create_commitment(5, 2468)

    plan = helper_module.build_confidential_transfer_from(
        owner_commitment=owner,
        receiver_commitment=receiver,
        allowance_commitment=allowance,
        amount=1.5,
        amount_blinding=1357,
        next_nonce=7,
    )

    reconstructed_owner = (
        plan["new_owner_commitment"] * plan["amount_commitment"]
    ) % helper_module.p
    reconstructed_receiver = (
        plan["new_receiver_commitment"] * helper_module.mod_inverse(plan["amount_commitment"])
    ) % helper_module.p
    reconstructed_allowance = (
        plan["new_allowance_commitment"] * plan["amount_commitment"]
    ) % helper_module.p
    assert reconstructed_owner == owner
    assert reconstructed_receiver == receiver
    assert reconstructed_allowance == allowance
    assert plan["nonce"] == 7


def test_build_mint_matches_expected(helper_module):
    current = helper_module.create_commitment(3, 111)
    plan = helper_module.build_mint(
        receiver_commitment=current,
        amount=4.5,
        amount_blinding=222,
        next_nonce=5,
    )

    expected = (current * plan["amount_commitment"]) % helper_module.p
    assert plan["new_receiver_commitment"] == expected
    assert plan["nonce"] == 5


def test_build_burn_matches_expected(helper_module):
    current = helper_module.create_commitment(7, 321)
    plan = helper_module.build_burn(
        from_commitment=current,
        amount=2,
        amount_blinding=654,
        next_nonce=3,
    )

    expected = (current * helper_module.mod_inverse(plan["amount_commitment"])) % helper_module.p
    assert plan["new_from_commitment"] == expected
    assert plan["nonce"] == 3


def test_random_blinding_within_modulus(helper_module):
    values = [helper_module.random_blinding() for _ in range(32)]
    assert all(0 <= value < helper_module.p for value in values)


def test_commitment_account_round_trip(helper_module):
    incoming = helper_module.create_commitment(5, 1111)
    outgoing = helper_module.create_commitment(2, 2222)
    account = helper_module.CommitmentAccount()

    account.apply_incoming(incoming)
    after_in = (helper_module.ZERO_COMMITMENT * incoming) % helper_module.p
    assert account.commitment == after_in

    account.apply_outgoing(outgoing)
    expected = (after_in * helper_module.mod_inverse(outgoing)) % helper_module.p
    assert account.commitment == expected
