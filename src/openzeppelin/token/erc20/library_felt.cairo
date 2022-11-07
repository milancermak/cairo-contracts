# SPDX-License-Identifier: MIT
# OpenZeppelin Contracts for Cairo v0.1.0 (token/erc20/library.cairo)

%lang starknet

from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.math import (
    assert_not_zero,
    assert_lt,
    assert_le,
    assert_le_felt,
    split_felt,
)
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.uint256 import Uint256, uint256_check

from openzeppelin.utils.constants import UINT8_MAX

# TODO: think through wrapping overflow attacks, e.g. on _transfer

const MAX_FELT = 0 - 1
const MAX_HIGH = 10633823966279327296825105735305134080
const HIGH_SHIFT = 2 ** 128

func _to_felt{range_check_ptr}(u : Uint256) -> (val : felt):
    uint256_check(u)
    assert_le(u.high, MAX_HIGH)
    let val = u.high * HIGH_SHIFT + u.low
    return (val)
end

func _to_u256{range_check_ptr}(val : felt) -> (val : Uint256):
    let (high, low) = split_felt(val)
    return (Uint256(low=low, high=high))
end

#
# Events
#

@event
func Transfer(from_ : felt, to : felt, value : Uint256):
end

@event
func Approval(owner : felt, spender : felt, value : Uint256):
end

#
# Storage
#

@storage_var
func ERC20_name() -> (name : felt):
end

@storage_var
func ERC20_symbol() -> (symbol : felt):
end

@storage_var
func ERC20_decimals() -> (decimals : felt):
end

@storage_var
func ERC20_total_supply() -> (total_supply : felt):
end

@storage_var
func ERC20_balances(account : felt) -> (balance : felt):
end

@storage_var
func ERC20_allowances(owner : felt, spender : felt) -> (allowance : felt):
end

namespace ERC20:
    #
    # Initializer
    #

    func initializer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        name : felt, symbol : felt, decimals : felt
    ):
        ERC20_name.write(name)
        ERC20_symbol.write(symbol)
        with_attr error_message("ERC20: decimals exceed 2^8"):
            assert_lt(decimals, UINT8_MAX)
        end
        ERC20_decimals.write(decimals)
        return ()
    end

    #
    # Public functions
    #

    func name{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (name : felt):
        let (name) = ERC20_name.read()
        return (name)
    end

    func symbol{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
        symbol : felt
    ):
        let (symbol) = ERC20_symbol.read()
        return (symbol)
    end

    func total_supply{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
        total_supply : Uint256
    ):
        let (val) = ERC20_total_supply.read()
        let (total_supply) = _to_u256(val)
        return (total_supply)
    end

    func decimals{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
        decimals : felt
    ):
        let (decimals) = ERC20_decimals.read()
        return (decimals)
    end

    func balance_of{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        account : felt
    ) -> (balance : Uint256):
        let (val) = ERC20_balances.read(account)
        let (balance) = _to_u256(val)
        return (balance)
    end

    func allowance{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        owner : felt, spender : felt
    ) -> (remaining : Uint256):
        let (val : felt) = ERC20_allowances.read(owner, spender)
        let (remaining) = _to_u256(val)
        return (remaining)
    end

    func transfer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        recipient : felt, amount : Uint256
    ):
        alloc_locals
        let (sender) = get_caller_address()
        let (val) = _to_felt(amount)
        _transfer(sender, recipient, val)
        Transfer.emit(sender, recipient, amount)
        return ()
    end

    func transfer_from{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        sender : felt, recipient : felt, amount : Uint256
    ) -> ():
        alloc_locals
        let (caller) = get_caller_address()
        let (val) = _to_felt(amount)
        # subtract allowance
        _spend_allowance(sender, caller, val)
        # execute transfer
        _transfer(sender, recipient, val)
        Transfer.emit(sender, recipient, amount)
        return ()
    end

    func approve{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        spender : felt, amount : Uint256
    ):
        let (caller) = get_caller_address()
        let (val) = _to_felt(amount)
        _approve(caller, spender, val)
        return ()
    end

    func increase_allowance{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        spender : felt, added_value : Uint256
    ) -> ():
        let (caller) = get_caller_address()
        let (val) = _to_felt(added_value)
        let (current_allowance : felt) = ERC20_allowances.read(caller, spender)

        # add allowance
        with_attr error_message("ERC20: allowance overflow"):
            let new_allowance = current_allowance + val
            assert_le_felt(current_allowance, new_allowance)
        end

        _approve(caller, spender, new_allowance)
        return ()
    end

    func decrease_allowance{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        spender : felt, subtracted_value : Uint256
    ) -> ():
        let (caller) = get_caller_address()
        let (val) = _to_felt(subtracted_value)
        let (current_allowance : felt) = ERC20_allowances.read(owner=caller, spender=spender)

        with_attr error_message("ERC20: allowance below zero"):
            let new_allowance = current_allowance - val
            assert_le_felt(new_allowance, current_allowance)
        end

        _approve(caller, spender, new_allowance)
        return ()
    end

    #
    # Internal
    #

    func _mint{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        recipient : felt, amount : Uint256
    ):
        alloc_locals

        with_attr error_message("ERC20: cannot mint to the zero address"):
            assert_not_zero(recipient)
        end

        let (val) = _to_felt(amount)
        let (supply : felt) = ERC20_total_supply.read()
        with_attr error_message("ERC20: mint overflow"):
            let new_supply = supply + val
            assert_le_felt(supply, new_supply)
        end
        ERC20_total_supply.write(new_supply)

        let (balance : felt) = ERC20_balances.read(account=recipient)
        # overflow is not possible because sum is guaranteed to be less than total supply
        # which we check for overflow below
        ERC20_balances.write(recipient, balance + val)

        Transfer.emit(0, recipient, amount)
        return ()
    end

    func _burn{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        account : felt, amount : Uint256
    ):
        alloc_locals

        with_attr error_message("ERC20: cannot burn from the zero address"):
            assert_not_zero(account)
        end

        let (val) = _to_felt(amount)
        let (balance : felt) = ERC20_balances.read(account)
        with_attr error_message("ERC20: burn amount exceeds balance"):
            let new_balance = balance - val
            assert_le_felt(new_balance, balance)
        end

        ERC20_balances.write(account, new_balance)

        let (supply : felt) = ERC20_total_supply.read()
        ERC20_total_supply.write(supply - val)
        Transfer.emit(account, 0, amount)
        return ()
    end

    func _transfer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        sender : felt, recipient : felt, amount : felt
    ):
        alloc_locals

        with_attr error_message("ERC20: cannot transfer from the zero address"):
            assert_not_zero(sender)
        end

        with_attr error_message("ERC20: cannot transfer to the zero address"):
            assert_not_zero(recipient)
        end

        let (sender_balance : felt) = ERC20_balances.read(account=sender)
        with_attr error_message("ERC20: transfer amount exceeds balance"):
            let new_sender_balance = sender_balance - amount
            assert_le_felt(new_sender_balance, sender_balance)
        end

        ERC20_balances.write(sender, new_sender_balance)

        # add to recipient
        let (recipient_balance : felt) = ERC20_balances.read(account=recipient)
        # overflow is not possible because sum is guaranteed by mint to be less than total supply
        ERC20_balances.write(recipient, recipient_balance + amount)

        # let (u) = _to_u256(amount)
        # Transfer.emit(sender, recipient, u)
        return ()
    end

    func _approve{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        owner : felt, spender : felt, amount : felt
    ):
        with_attr error_message("ERC20: cannot approve from the zero address"):
            assert_not_zero(owner)
        end

        with_attr error_message("ERC20: cannot approve to the zero address"):
            assert_not_zero(spender)
        end

        ERC20_allowances.write(owner, spender, amount)
        let (u) = _to_u256(amount)
        Approval.emit(owner, spender, u)
        return ()
    end

    func _spend_allowance{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        owner : felt, spender : felt, amount : felt
    ):
        alloc_locals

        let (current_allowance : felt) = ERC20_allowances.read(owner, spender)
        if current_allowance == MAX_FELT:
            return ()
        end

        with_attr error_message("ERC20: insufficient allowance"):
            let new_allowance = current_allowance - amount
            assert_le_felt(new_allowance, current_allowance)
        end

        _approve(owner, spender, new_allowance)
        return ()
    end
end
