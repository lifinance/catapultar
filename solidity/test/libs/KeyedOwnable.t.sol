// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";

import { MockKeyedOwnable } from "../mocks/MockKeyedOwnable.sol";

import { Base64 } from "solady/src/utils/Base64.sol";
import { P256 } from "solady/src/utils/P256.sol";
import { WebAuthn } from "solady/src/utils/WebAuthn.sol";

// From Solady
contract P256VerifierEtcher is Test {
    bytes internal constant _VERIFIER_BYTECODE =
        hex"3d604052610216565b60008060006ffffffffeffffffffffffffffffffffff60601b19808687098188890982838389096004098384858485093d510985868b8c096003090891508384828308850385848509089650838485858609600809850385868a880385088509089550505050808188880960020991505093509350939050565b81513d83015160408401516ffffffffeffffffffffffffffffffffff60601b19808384098183840982838388096004098384858485093d510985868a8b096003090896508384828308850385898a09089150610102848587890960020985868787880960080987038788878a0387088c0908848b523d8b015260408a0152565b505050505050505050565b81513d830151604084015185513d87015160408801518361013d578287523d870182905260408701819052610102565b80610157578587523d870185905260408701849052610102565b6ffffffffeffffffffffffffffffffffff60601b19808586098183840982818a099850828385830989099750508188830383838809089450818783038384898509870908935050826101be57836101be576101b28a89610082565b50505050505050505050565b808485098181860982828a09985082838a8b0884038483860386898a09080891506102088384868a0988098485848c09860386878789038f088a0908848d523d8d015260408c0152565b505050505050505050505050565b6020357fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325513d6040357f7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a88111156102695782035b60206108005260206108205260206108405280610860526002830361088052826108a0526ffffffffeffffffffffffffffffffffff60601b198060031860205260603560803560203d60c061080060055afa60203d1416837f5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b8585873d5189898a09080908848384091484831085851016888710871510898b108b151016609f3611161616166103195760206080f35b60809182523d820152600160c08190527f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2966102009081527f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f53d909101526102405261038992509050610100610082565b610397610200610400610082565b6103a7610100608061018061010d565b6103b7610200608061028061010d565b6103c861020061010061030061010d565b6103d961020061018061038061010d565b6103e9610400608061048061010d565b6103fa61040061010061050061010d565b61040b61040061018061058061010d565b61041c61040061020061060061010d565b61042c610600608061068061010d565b61043d61060061010061070061010d565b61044e61060061018061078061010d565b81815182350982825185098283846ffffffffeffffffffffffffffffffffff60601b193d515b82156105245781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f71c16610600888a1b60f51c16176040810151801585151715610564578061055357506105fe565b81513d8301519750955093506105fe565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a015109089350836105b957806105b9576105a9898c8c610008565b9a509b50995050505050506105fe565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b5082156106af5781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f51c16610600888a1b60f31c161760408101518015851517156106ef57806106de5750610789565b81513d830151975095509350610789565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a01510908935083610744578061074457610734898c8c610008565b9a509b5099505050505050610789565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b50600488019760fb19016104745750816107a2573d6040f35b81610860526002810361088052806108a0523d3d60c061080060055afa898983843d513d510987090614163d525050505050505050503d3df3fea264697066735822122063ce32ec0e56e7893a1f6101795ce2e38aca14dd12adb703c71fe3bee27da71e64736f6c634300081a0033";

    bytes internal constant _PASSTHROUGH_BYTECODE = hex"600160005260206000f3";

    function _etchBytecode(
        address target,
        bytes memory bytecode,
        bool active
    ) internal {
        if (target == P256.RIP_PRECOMPILE) {
            if (active && _hasNativeRipPrecompile()) return;
            if (!active && _hasNativeRipPrecompile()) {
                /// @solidity memory-safe-assembly
                assembly {
                    return(0x00, 0x00)
                }
            }
        }

        if (active) if (target.code.length == 0) vm.etch(target, bytecode);
        else if (target.code.length != 0) vm.etch(target, "");
    }

    function _hasNativeRipPrecompile() internal view returns (bool) {
        return P256.hasPrecompile() && P256.RIP_PRECOMPILE.code.length == 0;
    }

    function _etchPassthroughBytecode(
        address target,
        bool active
    ) internal {
        _etchBytecode(target, _PASSTHROUGH_BYTECODE, active);
    }

    function _etchVerifierBytecode(
        address target,
        bool active
    ) internal {
        _etchBytecode(target, _VERIFIER_BYTECODE, active);
    }

    function _etchRipPrecompilePassthrough(
        bool active
    ) internal {
        _etchPassthroughBytecode(P256.RIP_PRECOMPILE, active);
    }

    function _etchVerifierPassthrough(
        bool active
    ) internal {
        _etchPassthroughBytecode(P256.VERIFIER, active);
    }

    function _etchRipPrecompile(
        bool active
    ) internal {
        _etchVerifierBytecode(P256.RIP_PRECOMPILE, active);
    }

    function _etchVerifier(
        bool active
    ) internal {
        _etchVerifierBytecode(P256.VERIFIER, active);
    }
}

contract KeyedOwnableTest is P256VerifierEtcher {
    MockKeyedOwnable ownable;

    address initialOwner;
    uint256 initialKey;

    function makeP256(
        string memory seed
    ) internal pure returns (uint256 privateKey, bytes32[] memory publicKey) {
        privateKey = uint256(keccak256(bytes(seed)));
        while (privateKey == 0 || privateKey >= P256.N) privateKey = uint256(keccak256(abi.encode(privateKey)));
        (uint256 x, uint256 y) = vm.publicKeyP256(privateKey);
        publicKey = new bytes32[](2);
        publicKey[0] = bytes32(x);
        publicKey[1] = bytes32(y);
    }

    function setUp() public {
        _etchRipPrecompile(true);
        _etchVerifier(true);

        ownable = new MockKeyedOwnable();
        (initialOwner, initialKey) = makeAddrAndKey("owner");

        bytes32[] memory owner = new bytes32[](1);
        owner[0] = bytes32(uint256(uint160(initialOwner)));
        ownable.setOwnership(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, owner);
    }

    function test_transferOwnership() external {
        // Validate that owner slot 1 is clean
        bytes32 cleanSlot = ownable.getPublicKeySlice(1);
        assertEq(cleanSlot, 0);

        (KeyedOwnable.PublicKeyType ktp, bytes32[] memory key) = ownable.getPublicKey();

        bytes32[] memory expectedKey = new bytes32[](1);
        expectedKey[0] = bytes32(uint256(uint160(initialOwner)));
        assertEq(uint8(ktp), uint8(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract));
        assertEq(key, expectedKey);

        expectedKey[0] = bytes32(uint256(uint160(makeAddr("newOwner"))));
        // New ECDSA owner.
        vm.prank(ownable.owner());
        vm.expectEmit();
        emit KeyedOwnable.OwnershipTransferred(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, expectedKey);
        ownable.transferOwnership(makeAddr("newOwner"));

        (ktp, key) = ownable.getPublicKey();
        assertEq(uint8(ktp), uint8(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract));
        assertEq(key, expectedKey);

        // New P256 owner
        (, bytes32[] memory publickeyP256) = makeP256("P256Owner");

        vm.prank(ownable.owner());
        vm.expectEmit();
        emit KeyedOwnable.OwnershipTransferred(KeyedOwnable.PublicKeyType.P256, publickeyP256);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.P256, publickeyP256);

        (ktp, key) = ownable.getPublicKey();
        assertEq(uint8(ktp), uint8(KeyedOwnable.PublicKeyType.P256));
        assertEq(key, publickeyP256);

        (, publickeyP256) = makeP256("WebAuthnP256Owner");

        vm.prank(address(ownable));
        vm.expectEmit();
        emit KeyedOwnable.OwnershipTransferred(KeyedOwnable.PublicKeyType.WebAuthnP256, publickeyP256);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.WebAuthnP256, publickeyP256);

        (ktp, key) = ownable.getPublicKey();
        assertEq(uint8(ktp), uint8(KeyedOwnable.PublicKeyType.WebAuthnP256));
        assertEq(key, publickeyP256);

        vm.expectRevert(abi.encodeWithSelector(KeyedOwnable.DirtyEthereumAddress.selector, (publickeyP256[0])));
        ownable.owner();

        // Set owner to an ECDSA again:

        expectedKey[0] = bytes32(uint256(uint160(makeAddr("newOwner"))));
        // New ECDSA owner.
        vm.prank(address(ownable));
        vm.expectEmit();
        emit KeyedOwnable.OwnershipTransferred(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, expectedKey);
        ownable.transferOwnership(makeAddr("newOwner"));

        (ktp, key) = ownable.getPublicKey();
        assertEq(uint8(ktp), uint8(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract));
        assertEq(key, expectedKey);

        // Notice that we have a dirty slot now.
        bytes32 dirtySlot = ownable.getPublicKeySlice(1);
        assertNotEq(dirtySlot, 0);
    }

    function testRevert_transferOwnership_invalid_key() external {
        vm.startPrank(address(ownable));

        // ECDSA
        bytes32[] memory owner = new bytes32[](1);

        // 0
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, owner);

        // dirty Ethereum address.
        owner[0] = keccak256(bytes("newOwner"));
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, owner);

        // 0
        owner[0] = bytes32(0);
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, owner);

        owner = new bytes32[](1);
        // dirty Ethereum address.
        owner[0] = keccak256(bytes("newOwner"));
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, owner);

        // Too long
        owner = new bytes32[](2);
        owner[0] = bytes32(uint256(uint160(makeAddr("newOwner"))));
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, owner);

        // Too short
        owner = new bytes32[](0);
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, owner);

        // P256

        // too short
        owner = new bytes32[](0);
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.P256, owner);
        owner = new bytes32[](1);
        owner[0] = keccak256(bytes("x"));
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.P256, owner);

        // 0
        owner = new bytes32[](2);
        owner[0] = keccak256(bytes("x"));
        owner[1] = bytes32(0);
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.P256, owner);
        owner[1] = keccak256(bytes("y"));
        owner[0] = bytes32(0);
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.P256, owner);

        // too long
        owner = new bytes32[](3);
        owner[0] = keccak256(bytes("x"));
        owner[1] = keccak256(bytes("y"));
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.P256, owner);

        // P256 WebAuthnP256

        // too short
        owner = new bytes32[](0);
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.WebAuthnP256, owner);
        owner = new bytes32[](1);
        owner[0] = keccak256(bytes("x"));
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.WebAuthnP256, owner);

        // 0
        owner = new bytes32[](2);
        owner[0] = keccak256(bytes("x"));
        owner[1] = bytes32(0);
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.WebAuthnP256, owner);
        owner[1] = keccak256(bytes("y"));
        owner[0] = bytes32(0);
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.WebAuthnP256, owner);

        // too long
        owner = new bytes32[](3);
        owner[0] = keccak256(bytes("x"));
        owner[1] = keccak256(bytes("y"));
        vm.expectRevert(KeyedOwnable.InvalidKey.selector);
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.WebAuthnP256, owner);
    }

    function test_validateSignature_ECDSA() external view {
        // Validate that the owner is who we expect.
        assertEq(ownable.owner(), initialOwner);

        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes32 vs;

        bytes32 randomDigest = keccak256(bytes("randomDigest"));
        (r, vs) = vm.signCompact(initialKey, randomDigest);
        bytes memory compactSignature = abi.encodePacked(r, vs);
        (v, r, s) = vm.sign(initialKey, randomDigest);
        bytes memory signature = abi.encodePacked(r, s, v);

        assertTrue(ownable.validateSignature(randomDigest, compactSignature));
        assertTrue(ownable.validateSignature(randomDigest, signature));

        assertFalse(ownable.validateSignature(keccak256(bytes("anotherDigest")), compactSignature));
        assertFalse(ownable.validateSignature(keccak256(bytes("anotherDigest")), signature));
    }

    function test_validateSignature_1271() external {
        // Validate that the owner is who we expect.
        assertEq(ownable.owner(), initialOwner);
        address smartAccountOwner = address(ownable);

        // Make a new account and transfer ownership to our original SA.
        ownable = new MockKeyedOwnable();
        (initialOwner, initialKey) = makeAddrAndKey("owner");

        bytes32[] memory owner = new bytes32[](1);
        owner[0] = bytes32(uint256(uint160(smartAccountOwner)));
        ownable.setOwnership(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, owner);

        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes32 vs;

        bytes32 randomDigest = keccak256(bytes("randomDigest"));
        (r, vs) = vm.signCompact(initialKey, randomDigest);
        bytes memory compactSignature = abi.encodePacked(r, vs);
        (v, r, s) = vm.sign(initialKey, randomDigest);
        bytes memory signature = abi.encodePacked(r, s, v);

        assertTrue(ownable.validateSignature(randomDigest, compactSignature));
        assertTrue(ownable.validateSignature(randomDigest, signature));

        assertFalse(ownable.validateSignature(keccak256(bytes("anotherDigest")), compactSignature));
        assertFalse(ownable.validateSignature(keccak256(bytes("anotherDigest")), signature));
    }

    function test_validateSignature_P256() external {
        // We need to switch the account to a P256 owner.
        (uint256 privatekeyP256, bytes32[] memory publickeyP256) = makeP256("WebAuthnP256Owner");
        vm.prank(address(ownable));
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.P256, publickeyP256);

        bytes32 randomDigest = keccak256(bytes("randomDigest"));

        (bytes32 r, bytes32 s) = vm.signP256(privatekeyP256, randomDigest);
        bytes memory signature = abi.encodePacked(r, P256.normalized(s), bytes2(0));

        assertTrue(ownable.validateSignature(randomDigest, signature));

        // Check if it works if we want to rehash the signature:
        bytes32 rehashedDigest = sha256(abi.encodePacked(randomDigest));
        assertEq(ownable.validateSignature(rehashedDigest, signature), false);

        (r, s) = vm.signP256(privatekeyP256, rehashedDigest);
        signature = abi.encodePacked(r, P256.normalized(s), bytes2(0));
        bytes memory signatureRehash = abi.encodePacked(r, P256.normalized(s), bytes2(uint16(1)));

        // We now have the choice whether we wanna directly verify the digest or through rehashing first.
        assertEq(ownable.validateSignature(rehashedDigest, signature), true);
        assertEq(ownable.validateSignature(randomDigest, signatureRehash), true);

        assertEq(ownable.validateSignature(randomDigest, signature), false);
        assertEq(ownable.validateSignature(rehashedDigest, signatureRehash), false);
    }

    function _signedWebAuthnAuth(
        bytes32 digest,
        uint256 privatekeyP256
    ) internal pure returns (WebAuthn.WebAuthnAuth memory auth) {
        bytes memory challenge = abi.encode(digest);

        // Data is stolen from Solady/test/WebAuthn.t.sol
        auth.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a";
        auth.clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64.encode(challenge, true, true),
                '","origin":"http://localhost:3005","crossOrigin":false}'
            )
        );
        auth.challengeIndex = 23;
        auth.typeIndex = 1;
        // Create signable messageHash.
        bytes32 messageHash = sha256(abi.encodePacked(auth.authenticatorData, sha256(bytes(auth.clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(privatekeyP256, messageHash);
        auth.r = r;
        auth.s = P256.normalized(s);
    }

    function test_validateSignature_WebAuthn() external {
        // We need to switch the account to a P256 owner.
        (uint256 privatekeyP256, bytes32[] memory publickeyP256) = makeP256("WebAuthnP256Owner");
        vm.prank(address(ownable));
        ownable.transferOwnership(KeyedOwnable.PublicKeyType.WebAuthnP256, publickeyP256);

        bytes32 randomDigest = keccak256(bytes("randomDigest"));
        WebAuthn.WebAuthnAuth memory auth = _signedWebAuthnAuth(randomDigest, privatekeyP256);
        bytes memory signature = abi.encode(auth, false);

        assertTrue(ownable.validateSignature(randomDigest, signature));

        // Check if it works if we want to rehash the signature:
        bytes32 rehashedDigest = sha256(abi.encodePacked(randomDigest));
        assertEq(ownable.validateSignature(rehashedDigest, signature), false);

        auth = _signedWebAuthnAuth(rehashedDigest, privatekeyP256);
        signature = abi.encodePacked(abi.encode(auth), false);
        bytes memory signatureRehash = abi.encodePacked(abi.encode(auth), true);

        // We now have the choice whether we wanna directly verify the digest or through rehashing first.
        assertEq(ownable.validateSignature(rehashedDigest, signature), true);
        assertEq(ownable.validateSignature(randomDigest, signatureRehash), true);

        assertEq(ownable.validateSignature(randomDigest, signature), false);
        assertEq(ownable.validateSignature(rehashedDigest, signatureRehash), false);
    }
}
