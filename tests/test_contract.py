import pytest


def mint_to(contract, helper, to, amount, *, block_num, nonce, receiver_commitment=None, blinding=123456):
    params = helper.build_mint(
        receiver_commitment=receiver_commitment or helper.ZERO_COMMITMENT,
        amount=amount,
        amount_blinding=blinding,
        next_nonce=nonce,
    )
    contract.mint(
        to=to,
        amount=params["amount"],
        amount_commitment=params["amount_commitment"],
        new_receiver_commitment=params["new_receiver_commitment"],
        nonce=params["nonce"],
        environment={"block_num": block_num},
    )
    return params


def build_transfer(contract, helper, sender, receiver, amount, *, nonce, block_num, receiver_commitment=None, blinding=987654):
    sender_entry = contract.balance_commitments[sender]
    receiver_commitment = receiver_commitment or helper.ZERO_COMMITMENT
    plan = helper.build_confidential_transfer(
        sender_commitment=sender_entry["commitment"],
        receiver_commitment=receiver_commitment,
        amount=amount,
        amount_blinding=blinding,
        next_nonce=nonce,
    )
    contract.confidential_transfer(
        to=receiver,
        amount_commitment=plan["amount_commitment"],
        new_sender_commitment=plan["new_sender_commitment"],
        new_receiver_commitment=plan["new_receiver_commitment"],
        nonce=plan["nonce"],
        signer=sender,
        environment={"block_num": block_num},
    )
    return plan


def test_seed_initializes_metadata(contract):
    metadata = contract.get_metadata()
    assert metadata["name"] == "Confidential Commitment Token"
    assert metadata["operator"] == "operator"
    assert metadata["total_supply"] == 0
    assert metadata["supply_commitment"] == 1


def test_mint_updates_supply_and_commitments(contract, helper_module):
    params = mint_to(
        contract,
        helper_module,
        to="alice",
        amount=10.5,
        block_num=1,
        nonce=1,
        blinding=111,
    )

    balance = contract.balance_commitments["alice"]
    assert balance["commitment"] == params["new_receiver_commitment"]
    assert balance["last_updated"] == 1
    assert balance["updates"] == 1

    metadata = contract.get_metadata()
    assert str(metadata["total_supply"]) == "10.5"
    assert metadata["supply_commitment"] == params["amount_commitment"] % helper_module.p
    assert contract.get_nonce(address="operator") == 1


def test_confidential_transfer_updates_state(contract, helper_module):
    mint_params = mint_to(
        contract,
        helper_module,
        to="alice",
        amount=9.5,
        block_num=1,
        nonce=1,
        blinding=222,
    )

    transfer = build_transfer(
        contract,
        helper_module,
        sender="alice",
        receiver="bob",
        amount=2.5,
        nonce=1,
        block_num=2,
    )

    alice = contract.balance_commitments["alice"]
    bob = contract.balance_commitments["bob"]

    assert alice["commitment"] == transfer["new_sender_commitment"]
    assert alice["updates"] == 2
    assert alice["last_updated"] == 2
    assert bob["commitment"] == transfer["new_receiver_commitment"]
    assert bob["updates"] == 1
    assert bob["last_updated"] == 2
    assert contract.get_nonce(address="alice") == 1
    assert str(contract.get_metadata()["total_supply"]) == str(mint_params["amount"])
    assert contract.verify_supply_invariant()["ok"]


def test_confidential_transfer_rejects_bad_nonce(contract, helper_module):
    mint_to(
        contract,
        helper_module,
        to="alice",
        amount=5,
        block_num=1,
        nonce=1,
    )

    sender_commitment = contract.balance_commitments["alice"]["commitment"]
    plan = helper_module.build_confidential_transfer(
        sender_commitment=sender_commitment,
        receiver_commitment=helper_module.ZERO_COMMITMENT,
        amount=1,
        amount_blinding=333,
        next_nonce=2,
    )

    with pytest.raises(AssertionError):
        contract.confidential_transfer(
            to="bob",
            amount_commitment=plan["amount_commitment"],
            new_sender_commitment=plan["new_sender_commitment"],
            new_receiver_commitment=plan["new_receiver_commitment"],
            nonce=plan["nonce"],
            signer="alice",
            environment={"block_num": 2},
        )


def test_confidential_transfer_detects_commitment_mismatch(contract, helper_module):
    mint_to(
        contract,
        helper_module,
        to="alice",
        amount=7,
        block_num=1,
        nonce=1,
    )

    sender_commitment = contract.balance_commitments["alice"]["commitment"]
    plan = helper_module.build_confidential_transfer(
        sender_commitment=sender_commitment,
        receiver_commitment=helper_module.ZERO_COMMITMENT,
        amount=3,
        amount_blinding=444,
        next_nonce=1,
    )

    with pytest.raises(AssertionError):
        contract.confidential_transfer(
            to="bob",
            amount_commitment=plan["amount_commitment"],
            new_sender_commitment=plan["new_sender_commitment"],
            new_receiver_commitment=plan["new_receiver_commitment"] ^ 1,
            nonce=plan["nonce"],
            signer="alice",
            environment={"block_num": 2},
        )


def test_confidential_approve_and_transfer_from(contract, helper_module):
    mint_to(
        contract,
        helper_module,
        to="alice",
        amount=6,
        block_num=1,
        nonce=1,
    )

    approval = helper_module.build_confidential_approve(
        current_allowance_commitment=helper_module.ZERO_COMMITMENT,
        allowance_amount=3,
        allowance_blinding=555,
        next_nonce=1,
    )

    contract.confidential_approve(
        spender="bob",
        allowance_commitment=approval["allowance_commitment"],
        nonce=approval["nonce"],
        signer="alice",
        environment={"block_num": 2},
    )

    plan = helper_module.build_confidential_transfer_from(
        owner_commitment=contract.balance_commitments["alice"]["commitment"],
        receiver_commitment=helper_module.ZERO_COMMITMENT,
        allowance_commitment=contract.approvals["alice", "bob"]["commitment"],
        amount=2,
        amount_blinding=666,
        next_nonce=1,
    )

    contract.confidential_transfer_from(
        owner="alice",
        to="charlie",
        amount_commitment=plan["amount_commitment"],
        new_owner_commitment=plan["new_owner_commitment"],
        new_receiver_commitment=plan["new_receiver_commitment"],
        new_allowance_commitment=plan["new_allowance_commitment"],
        nonce=plan["nonce"],
        signer="bob",
        environment={"block_num": 3},
    )

    alice = contract.balance_commitments["alice"]
    charlie = contract.balance_commitments["charlie"]
    allowance = contract.approvals["alice", "bob"]

    assert alice["commitment"] == plan["new_owner_commitment"]
    assert charlie["commitment"] == plan["new_receiver_commitment"]
    assert allowance["commitment"] == plan["new_allowance_commitment"]
    assert contract.get_nonce(address="bob") == 1


def test_confidential_transfer_from_requires_approval(contract, helper_module):
    mint_to(
        contract,
        helper_module,
        to="alice",
        amount=4,
        block_num=1,
        nonce=1,
    )

    owner_commitment = contract.balance_commitments["alice"]["commitment"]
    dummy_allowance = helper_module.create_commitment(3, 777)

    plan = helper_module.build_confidential_transfer_from(
        owner_commitment=owner_commitment,
        receiver_commitment=helper_module.ZERO_COMMITMENT,
        allowance_commitment=dummy_allowance,
        amount=1,
        amount_blinding=888,
        next_nonce=1,
    )

    with pytest.raises(AssertionError):
        contract.confidential_transfer_from(
            owner="alice",
            to="bob",
            amount_commitment=plan["amount_commitment"],
            new_owner_commitment=plan["new_owner_commitment"],
            new_receiver_commitment=plan["new_receiver_commitment"],
            new_allowance_commitment=plan["new_allowance_commitment"],
            nonce=plan["nonce"],
            signer="bob",
            environment={"block_num": 2},
        )


def test_burn_reduces_supply(contract, helper_module):
    mint_to(
        contract,
        helper_module,
        to="alice",
        amount=10,
        block_num=1,
        nonce=1,
    )

    burn = helper_module.build_burn(
        from_commitment=contract.balance_commitments["alice"]["commitment"],
        amount=4,
        amount_blinding=999,
        next_nonce=1,
    )

    contract.burn(
        from_address="alice",
        amount=burn["amount"],
        amount_commitment=burn["amount_commitment"],
        new_from_commitment=burn["new_from_commitment"],
        nonce=burn["nonce"],
        signer="alice",
        environment={"block_num": 2},
    )

    metadata = contract.get_metadata()
    assert str(metadata["total_supply"]) == "6"
    assert contract.get_nonce(address="alice") == 1


def test_operator_can_force_burn(contract, helper_module):
    params = mint_to(
        contract,
        helper_module,
        to="alice",
        amount=8,
        block_num=1,
        nonce=1,
    )

    burn = helper_module.build_burn(
        from_commitment=contract.balance_commitments["alice"]["commitment"],
        amount=3,
        amount_blinding=1010,
        next_nonce=2,
    )

    contract.burn(
        from_address="alice",
        amount=burn["amount"],
        amount_commitment=burn["amount_commitment"],
        new_from_commitment=burn["new_from_commitment"],
        nonce=burn["nonce"],
        environment={"block_num": 2},
    )

    metadata = contract.get_metadata()
    assert str(metadata["total_supply"]) == "5"
    assert contract.get_nonce(address="operator") == 2
    assert metadata["supply_commitment"] == (
        params["amount_commitment"] * helper_module.mod_inverse(burn["amount_commitment"] % helper_module.p, helper_module.p)
    ) % helper_module.p


def test_get_nonce_tracks_progress(contract, helper_module):
    mint_to(
        contract,
        helper_module,
        to="alice",
        amount=4,
        block_num=1,
        nonce=1,
    )

    assert contract.get_nonce(address="alice") == 0

    build_transfer(
        contract,
        helper_module,
        sender="alice",
        receiver="bob",
        amount=1,
        nonce=1,
        block_num=2,
    )

    assert contract.get_nonce(address="alice") == 1


def test_verify_supply_invariant_identifies_tamper(contract, helper_module):
    mint_to(
        contract,
        helper_module,
        to="alice",
        amount=5,
        block_num=1,
        nonce=1,
    )

    assert contract.verify_supply_invariant()["ok"]

    entry = contract.balance_commitments["alice"]
    entry["commitment"] = (entry["commitment"] * 3) % helper_module.p
    contract.balance_commitments["alice"] = entry

    assert not contract.verify_supply_invariant()["ok"]
