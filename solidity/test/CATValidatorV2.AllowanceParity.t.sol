// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../src/CATValidator.sol";
import { CATValidatorV2 } from "../src/CATValidatorV2.sol";
import { AllowanceSpend } from "../src/libs/LibExecutionConstraint.sol";

/// @dev Exposes v1's allowance loop.
contract V1Loop is CATValidator {
    function run(
        address destination,
        address source,
        AllowanceSpend[] calldata allowances
    ) external {
        _handleAllowances(destination, source, allowances);
    }
}

/// @dev Exposes V2's recording copy of the loop.
contract V2Loop is CATValidatorV2 {
    constructor() CATValidatorV2(address(0)) { }

    function run(
        address destination,
        address source,
        AllowanceSpend[] calldata allowances
    ) external returns (uint256[] memory) {
        return _handleAllowancesRecorded(destination, source, allowances);
    }
}

/// @dev Shared, ordered log of every `transferFrom` the tokens below receive.
contract PullLog {
    struct Pull {
        address token;
        address from;
        address to;
        uint256 amount;
    }

    Pull[] public pulls;

    function record(
        address from,
        address to,
        uint256 amount
    ) external {
        pulls.push(Pull(msg.sender, from, to, amount));
    }

    function count() external view returns (uint256) {
        return pulls.length;
    }
}

/// @dev Logs each `transferFrom` and, when `lossBps` is set, debits the sender
/// less than the nominal amount (stETH-style share rounding, scaled up).
contract LoggingToken is MockERC20 {
    PullLog immutable log;
    uint256 immutable lossBps;

    constructor(
        PullLog log_,
        uint256 lossBps_
    ) MockERC20("Logging", "LOG", 18) {
        log = log_;
        lossBps = lossBps_;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        log.record(from, to, amount);
        _transfer(from, to, amount);
        if (lossBps != 0) _mint(from, amount * lossBps / 10_000);
        return true;
    }
}

/// @dev `balanceOf` returns no data, so a MAGIC spend must fail closed. A
/// literal spend still reaches `transferFrom`, which is logged like the others.
contract BrokenBalanceOfToken {
    PullLog immutable log;

    constructor(
        PullLog log_
    ) {
        log = log_;
    }

    function balanceOf(
        address
    ) external pure { }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        log.record(from, to, amount);
        return true;
    }
}

/// @dev `transferFrom` returns no data (USDT-style); `balanceOf` works.
contract NoReturnToken {
    PullLog immutable log;

    constructor(
        PullLog log_
    ) {
        log = log_;
    }

    function balanceOf(
        address
    ) external pure returns (uint256) {
        return 1 ether;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external {
        log.record(from, to, amount);
    }
}

/**
 * V2 runs its own copy of v1's allowance loop when a program is committed, so
 * that each resolved spend can be recorded for the program. These tests pin the
 * contract that copy must keep: on the same escrow state and allowance order,
 * both loops make the same `transferFrom` calls in the same order, leave the
 * same balances, and revert with the same data. The recorded `spent[i]` is the
 * amount the loop passed to `transferFrom` for allowance `i`.
 */
contract CATValidatorV2AllowanceParityTest is Test {
    uint256 constant MAGIC = 1 << 255;
    uint256 constant SUPPLY = 1000 ether;
    uint256 constant MAX_AMOUNT = 2000 ether;

    struct Observation {
        bool ok;
        bytes data;
        PullLog.Pull[] pulls;
        uint256[] sourceBalances;
        uint256[] destinationBalances;
    }

    V1Loop v1;
    V2Loop v2;
    PullLog pullLog;
    address[] erc20s;
    address[] tokens;
    address source = makeAddr("source");
    address destination = makeAddr("destination");

    function setUp() external {
        v1 = new V1Loop();
        v2 = new V2Loop();
        pullLog = new PullLog();
        erc20s.push(address(new LoggingToken(pullLog, 0)));
        erc20s.push(address(new LoggingToken(pullLog, 100)));
        tokens = erc20s;
        tokens.push(address(new BrokenBalanceOfToken(pullLog)));
        tokens.push(address(0));
        tokens.push(address(new NoReturnToken(pullLog)));

        for (uint256 i; i < erc20s.length; ++i) {
            MockERC20 token = MockERC20(erc20s[i]);
            token.mint(source, SUPPLY);
            vm.startPrank(source);
            token.approve(address(v1), type(uint256).max);
            token.approve(address(v2), type(uint256).max);
            vm.stopPrank();
        }
    }

    /// Derives 1 to 4 allowances from the seed. Tokens are weighted toward the
    /// two ERC-20s so that multi-allowance same-token orders are common; a
    /// literal spend may exceed the balance and an allocation may fall below,
    /// equal, or exceed the spend, so the revert paths and the `allocated ==
    /// spend` boundary are exercised too.
    function allowancesFrom(
        bytes32 seed
    ) internal view returns (AllowanceSpend[] memory alls) {
        uint256 n = 1 + uint256(seed) % 4;
        alls = new AllowanceSpend[](n);
        for (uint256 i; i < n; ++i) {
            bytes32 word = keccak256(abi.encode(seed, i));
            uint256 kind = uint8(word[0]) % 9;
            address token = kind < 3 ? erc20s[0] : kind < 6 ? erc20s[1] : tokens[kind - 4];
            bool magic = uint8(word[1]) % 2 == 0;
            uint256 spend = magic ? MAGIC : uint256(uint64(bytes8(word << 16))) % MAX_AMOUNT;
            uint256 allocationKind = uint8(word[2]) % 4;
            uint256 allocated = allocationKind == 0
                ? uint256(uint64(bytes8(word << 80))) % MAX_AMOUNT
                : allocationKind == 1 ? (magic ? SUPPLY : spend) : type(uint256).max;
            alls[i] = AllowanceSpend({ token: token, allocated: allocated, spend: spend });
        }
    }

    function observe(
        address loop,
        AllowanceSpend[] memory alls
    ) internal returns (Observation memory o, uint256[] memory spent) {
        uint256 snapshot = vm.snapshotState();
        (o.ok, o.data) = loop.call(abi.encodeCall(V1Loop.run, (destination, source, alls)));
        if (o.ok && loop == address(v2)) spent = abi.decode(o.data, (uint256[]));

        uint256 n = pullLog.count();
        o.pulls = new PullLog.Pull[](n);
        for (uint256 i; i < n; ++i) {
            (o.pulls[i].token, o.pulls[i].from, o.pulls[i].to, o.pulls[i].amount) = pullLog.pulls(i);
        }
        o.sourceBalances = new uint256[](erc20s.length);
        o.destinationBalances = new uint256[](erc20s.length);
        for (uint256 i; i < erc20s.length; ++i) {
            o.sourceBalances[i] = MockERC20(erc20s[i]).balanceOf(source);
            o.destinationBalances[i] = MockERC20(erc20s[i]).balanceOf(destination);
        }
        vm.revertToState(snapshot);
    }

    function testFuzz_recordedLoopMatchesV1(
        bytes32 seed
    ) external {
        AllowanceSpend[] memory alls = allowancesFrom(seed);
        (Observation memory a,) = observe(address(v1), alls);
        (Observation memory b, uint256[] memory spent) = observe(address(v2), alls);

        assertEq(b.ok, a.ok, "same outcome");
        if (!a.ok) assertEq(b.data, a.data, "same revert data");
        assertEq(b.pulls.length, a.pulls.length, "same number of transferFrom calls");
        for (uint256 i; i < a.pulls.length; ++i) {
            assertEq(b.pulls[i].token, a.pulls[i].token, "same token");
            assertEq(b.pulls[i].from, a.pulls[i].from, "same from");
            assertEq(b.pulls[i].to, a.pulls[i].to, "same to");
            assertEq(b.pulls[i].amount, a.pulls[i].amount, "same amount");
        }
        assertEq(b.sourceBalances, a.sourceBalances, "same source balances");
        assertEq(b.destinationBalances, a.destinationBalances, "same destination balances");

        if (!a.ok) return;
        assertEq(spent.length, alls.length, "one register per allowance");
        assertEq(a.pulls.length, alls.length, "one transferFrom per allowance");
        for (uint256 i; i < alls.length; ++i) {
            assertEq(spent[i], a.pulls[i].amount, "spent[i] is the amount passed to transferFrom");
            assertEq(a.pulls[i].token, alls[i].token, "pulls follow the allowance order");
        }
    }

    /// A second MAGIC spend of a lossy token records the balance after the first
    /// pull left rounding behind: 1000 - 100 + 1 = 901, not 900.
    function test_magicAfterLossyPullRecordsTheFreshBalance() external {
        AllowanceSpend[] memory alls = new AllowanceSpend[](2);
        alls[0] = AllowanceSpend({ token: erc20s[1], allocated: type(uint256).max, spend: 100 ether });
        alls[1] = AllowanceSpend({ token: erc20s[1], allocated: type(uint256).max, spend: MAGIC });

        uint256[] memory spent = v2.run(destination, source, alls);

        assertEq(spent[0], 100 ether);
        assertEq(spent[1], 901 ether);
        assertEq(MockERC20(erc20s[1]).balanceOf(destination), 1001 ether);
    }
}
