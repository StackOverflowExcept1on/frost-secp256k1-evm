// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ECDSA} from "src/utils/cryptography/ECDSA.sol";
import {Secp256k1} from "src/utils/cryptography/Secp256k1.sol";
import {Memory} from "src/utils/Memory.sol";

contract ECDSATest is Test {
    function test_Recover() public view {
        // signature taken from https://github.com/ethereum/eth-keys/blob/main/README.md#quickstart
        uint256 memPtr = Memory.allocate(128);
        uint256 e = uint256(keccak256(abi.encodePacked("a message")));
        uint256 v = 27;
        uint256 r = 0xCCDA990DBA7864B79DC49158FEA269338A1CF5747BC4C4BF1B96823E31A0997E;
        uint256 s = 0x7D1E65C06C5BF128B7109E1B4B9BA8D1305DC33F32F624695B2FA8E02C12C1E0;
        vm.assertEq(
            ECDSA.recover(memPtr, e, v, r, s), uint256(uint160(address(0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1)))
        );
    }

    function test_RecoverWithValidEMin() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 e = 0;
        vm.assertNotEq(ECDSA.recover(memPtr, e, 27, 1, 1), 0);
    }

    function test_RecoverWithValidEMax() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 e = type(uint256).max;
        vm.assertNotEq(ECDSA.recover(memPtr, e, 27, 1, 1), 0);
    }

    function test_RecoverWithValidV27() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 v = 27;
        vm.assertNotEq(ECDSA.recover(memPtr, 0, v, 1, 1), 0);
    }

    function test_RecoverWithValidV28() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 v = 28;
        vm.assertNotEq(ECDSA.recover(memPtr, 0, v, 1, 1), 0);
    }

    function test_RecoverWithInvalidV() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 v = 42;
        vm.assertEq(ECDSA.recover(memPtr, 0, v, 1, 1), 0);
    }

    function test_RecoverWithValidRMin() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 r = 1;
        vm.assertNotEq(ECDSA.recover(memPtr, 0, 27, r, 1), 0);
    }

    function test_RecoverWithValidRMax() public view {
        uint256 memPtr = Memory.allocate(128);
        // `x = r = Secp256k1.N - 1` is not on curve
        uint256 r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F;
        vm.assertNotEq(ECDSA.recover(memPtr, 0, 27, r, 1), 0);
    }

    function test_RecoverWithValidROnCurve() public view {
        uint256 memPtr = Memory.allocate(128);
        // `x = r` is on curve
        uint256 r = 0x1A269EE780CE61E6124BD44A94DF8F76ABF6D924747941CAC7A8DDC506B3B63A;
        vm.assertNotEq(ECDSA.recover(memPtr, 0, 27, r, 1), 0);
    }

    function test_RecoverWithInvalidR0() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 r = 0;
        vm.assertEq(ECDSA.recover(memPtr, 0, 27, r, 1), 0);
    }

    function test_RecoverWithInvalidRSecp256k1N() public view {
        uint256 memPtr = Memory.allocate(128);
        // `x = r = Secp256k1.N` is on curve, but this exceeds maximum value of scalar
        uint256 r = Secp256k1.N;
        vm.assertEq(ECDSA.recover(memPtr, 0, 27, r, 1), 0);
    }

    function test_RecoverWithValidSMin() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 s = 1;
        vm.assertNotEq(ECDSA.recover(memPtr, 0, 27, 1, s), 0);
    }

    function test_RecoverWithValidSMax() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 s = Secp256k1.N - 1;
        vm.assertNotEq(ECDSA.recover(memPtr, 0, 27, 1, s), 0);
    }

    function test_RecoverWithInvalidS0() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 s = 0;
        vm.assertEq(ECDSA.recover(memPtr, 0, 27, 1, s), 0);
    }

    function test_RecoverWithInvalidSSecp256k1N() public view {
        uint256 memPtr = Memory.allocate(128);
        uint256 s = Secp256k1.N;
        vm.assertEq(ECDSA.recover(memPtr, 0, 27, 1, s), 0);
    }
}
