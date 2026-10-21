// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../src/CATValidator.sol";
import { CATValidatorV1_1 } from "../src/CATValidatorV1_1.sol";
import { AllowanceSpend } from "../src/libs/LibExecutionConstraint.sol";
import { CallbackERC20, ReceiptProbe } from "./CATValidatorV1_1.t.sol";

/// @dev Exposes the base's allowance loop.
contract HFLoop is CATValidator {
    function run(
        address destination,
        address source,
        AllowanceSpend[] calldata allowances
    ) external {
        _handleAllowances(destination, source, allowances);
    }
}

/// @dev Exposes v1.1's allowance loop and reads what it published, in the same frame.
contract V11Loop is CATValidatorV1_1 {
    function run(
        address destination,
        address source,
        AllowanceSpend[] calldata allowances,
        address[] calldata tokens
    ) external returns (uint256[] memory published) {
        _handleAllowancesPulled(destination, source, allowances);
        published = new uint256[](tokens.length);
        for (uint256 i; i < tokens.length; ++i) {
            published[i] = this.pulled(tokens[i]);
        }
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

/// @dev Logs each `transferFrom` and, when `lossBps` is set, debits the sender less than the nominal amount.
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

/// @dev `balanceOf` returns no data, so a MAGIC spend reverts `BalanceOfFailed` on both loops.
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

/// @dev The v1.1 loop matches the base's transfers, balances and revert data, and publishes the summed spends as
/// `pulled`.
contract CATValidatorV1_1AllowanceParityTest is Test {
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

    HFLoop hf;
    V11Loop v11;
    PullLog pullLog;
    address[] erc20s;
    address[] tokens;
    address source = makeAddr("source");
    address destination = makeAddr("destination");

    function setUp() external {
        hf = new HFLoop();
        v11 = new V11Loop();
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
            token.approve(address(hf), type(uint256).max);
            token.approve(address(v11), type(uint256).max);
            vm.stopPrank();
        }
    }

    /// Derives 1 to 4 allowances weighted toward the two ERC-20s, with spends around the revert boundaries.
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
        bytes memory callData
    ) internal returns (Observation memory o, bytes memory ret) {
        uint256 snapshot = vm.snapshotState();
        (o.ok, ret) = loop.call(callData);
        o.data = ret;

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

    function testFuzz_loopMatchesTheBase(
        bytes32 seed
    ) external {
        AllowanceSpend[] memory alls = allowancesFrom(seed);
        (Observation memory a,) = observe(address(hf), abi.encodeCall(HFLoop.run, (destination, source, alls)));
        (Observation memory b, bytes memory ret) =
            observe(address(v11), abi.encodeCall(V11Loop.run, (destination, source, alls, tokens)));

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
        uint256[] memory published = abi.decode(ret, (uint256[]));
        uint256[] memory expected = new uint256[](tokens.length);
        uint256 next;
        for (uint256 i; i < alls.length; ++i) {
            assertEq(a.pulls[next].token, alls[i].token, "pulls follow the allowance order");
            uint256 spent = a.pulls[next++].amount;
            for (uint256 t; t < tokens.length; ++t) {
                if (tokens[t] == alls[i].token) expected[t] += spent;
            }
        }
        assertEq(next, a.pulls.length, "one transferFrom per token allowance");
        assertEq(published, expected, "pulled is the summed amounts passed to transferFrom");
    }

    /// A MAGIC spend of a token without a readable `balanceOf` fails closed on both loops (audit 6.2.1).
    function test_brokenBalanceOfFailsClosedOnBothLoops() external {
        address broken = tokens[2];
        AllowanceSpend[] memory alls = new AllowanceSpend[](1);
        alls[0] = AllowanceSpend({ token: broken, allocated: type(uint256).max, spend: MAGIC });
        address[] memory list = new address[](1);
        list[0] = broken;

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, broken));
        hf.run(destination, source, alls);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, broken));
        v11.run(destination, source, alls, list);
    }

    /// A token hook inside the loop reads zero, never a partial sum.
    function test_pulled_is_zero_inside_the_loop() external {
        CallbackERC20 cb = new CallbackERC20();
        ReceiptProbe hook = new ReceiptProbe();
        hook.config(address(v11), address(cb));
        cb.setHook(address(hook));
        cb.mint(source, SUPPLY);
        vm.prank(source);
        cb.approve(address(v11), type(uint256).max);

        AllowanceSpend[] memory alls = new AllowanceSpend[](3);
        for (uint256 i; i < 3; ++i) {
            alls[i] = AllowanceSpend({ token: address(cb), allocated: (i + 1) * 10, spend: (i + 1) * 10 });
        }
        address[] memory list = new address[](1);
        list[0] = address(cb);

        uint256[] memory published = v11.run(destination, source, alls, list);

        assertEq(hook.count(), 3, "one hook call per transfer");
        for (uint256 i; i < hook.count(); ++i) {
            assertEq(hook.at(i), 0, "hook reads zero");
        }
        assertEq(published[0], 60, "published after the last transfer");
    }

    /// A second MAGIC spend of a lossy token publishes the fresh balance, 1000 - 100 + 1 = 901, not 900.
    function test_magicAfterLossyPullPublishesTheFreshBalance() external {
        AllowanceSpend[] memory alls = new AllowanceSpend[](2);
        alls[0] = AllowanceSpend({ token: erc20s[1], allocated: type(uint256).max, spend: 100 ether });
        alls[1] = AllowanceSpend({ token: erc20s[1], allocated: type(uint256).max, spend: MAGIC });
        address[] memory list = new address[](1);
        list[0] = erc20s[1];

        uint256[] memory published = v11.run(destination, source, alls, list);

        assertEq(published[0], 1001 ether);
        assertEq(MockERC20(erc20s[1]).balanceOf(destination), 1001 ether);
    }
}
