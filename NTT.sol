/**
 *
 */
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN        NNNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                         ..../&@&#.       .###%@@@#, ..
/*Z:::::::::::::::::ZK:::::::K    K:::::KN:::::::N       N::::::N   OO:::::::::OO   X:::::X       X:::::X                      ...(@@* .... .           &#//%@@&,.
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::::N      N::::::N OO:::::::::::::OO X:::::X       X:::::X                    ..*@@.........              .@#%%(%&@&..
/*Z:::ZZZZZZZZ:::::Z K:::::::K   K::::::KN:::::::::N     N::::::NO:::::::OOO:::::::OX::::::X     X::::::X                   .*@( ........ .  .&@@@@.      .@%%%%%#&@@.
/*ZZZZZ     Z:::::Z  KK::::::K  K:::::KKKN::::::::::N    N::::::NO::::::O   O::::::OXXX:::::X   X::::::XX                ...&@ ......... .  &.     .@      /@%%%%%%&@@#
/*        Z:::::Z      K:::::K K:::::K   N:::::::::::N   N::::::NO:::::O     O:::::O   X:::::X X:::::X                   ..@( .......... .  &.     ,&      /@%%%%&&&&@@@.
/*       Z:::::Z       K::::::K:::::K    N:::::::N::::N  N::::::NO:::::O     O:::::O    X:::::X:::::X                   ..&% ...........     .@%(#@#      ,@%%%%&&&&&@@@%.
/*      Z:::::Z        K:::::::::::K     N::::::N N::::N N::::::NO:::::O     O:::::O     X:::::::::X                   ..,@ ............                 *@%%%&%&&&&&&@@@.
/*     Z:::::Z         K:::::::::::K     N::::::N  N::::N:::::::NO:::::O     O:::::O     X:::::::::X                  ..(@ .............             ,#@&&&&&&&&&&&&@@@@*
/*    Z:::::Z          K::::::K:::::K    N::::::N   N:::::::::::NO:::::O     O:::::O    X:::::X:::::X                   .*@..............  . ..,(%&@@&&&&&&&&&&&&&&&&@@@@,
/*   Z:::::Z           K:::::K K:::::K   N::::::N    N::::::::::NO:::::O     O:::::O   X:::::X X:::::X                 ...&#............. *@@&&&&&&&&&&&&&&&&&&&&@@&@@@@&
/*ZZZ:::::Z     ZZZZZKK::::::K  K:::::KKKN::::::N     N:::::::::NO::::::O   O::::::OXXX:::::X   X::::::XX               ...@/.......... *@@@@. ,@@.  &@&&&&&&@@@@@@@@@@@.
/*Z::::::ZZZZZZZZ:::ZK:::::::K   K::::::KN::::::N      N::::::::NO:::::::OOO:::::::OX::::::X     X::::::X               ....&#..........@@@, *@@&&&@% .@@@@@@@@@@@@@@@&
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N       N:::::::N OO:::::::::::::OO X:::::X       X:::::X                ....*@.,......,@@@...@@@@@@&..%@@@@@@@@@@@@@/
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N        N::::::N   OO:::::::::OO   X:::::X       X:::::X                   ...*@,,.....%@@@,.........%@@@@@@@@@@@@(
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN         NNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                      ...&@,....*@@@@@ ..,@@@@@@@@@@@@@&.
/*                                                                                                                                   ....,(&@@&..,,,/@&#*. .
/*                                                                                                                                    ......(&.,.,,/&@,.
/*                                                                                                                                      .....,%*.,*@%
/*                                                                                                                                    .#@@@&(&@*,,*@@%,..
/*                                                                                                                                    .##,,,**$.,,*@@@@@%.
/*                                                                                                                                     *(%%&&@(,,**@@@@@&
/*                                                                                                                                      . .  .#@((@@(*,**
/*                                                                                                                                             . (*. .
/*                                                                                                                                              .*/
///* Copyright (C) 2025 - Renaud Dubois, Simon Masson - This file is part of ZKNOX project
///* License: This software is licensed under MIT License
///* This Code may be reused including this header, license and copyright notice.
///* See LICENSE file at the root folder of the project.
///* FILE: ZKNOX_NTT.sol
///* Description: Compute Negative Wrap Convolution NTT as specified in EIP-NTT
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./NTTConstants.sol";

library NTT {
    uint256 internal constant Q = 8380417;
    uint256 internal constant N = 32;
    uint256 internal constant N_INV = 1453328; // N^-1 mod Q, вычисленное отдельно

    address internal constant CONSTANTS_ADDR =
        0x5FbDB2315678afecb367f032d93F642f64180aa3;

    function ntt(uint256[] memory a) internal view returns (uint256[] memory) {
        // Получаем массив psi_rev из контракта
        uint256[256] memory psi_rev = NTTConstants(CONSTANTS_ADDR).getPsiRev();
        uint256 n = a.length;
        uint256 t = n;
        uint256 m = 1;

        while (m < n) {
            t = t >> 1;
            for (uint256 i = 0; i < m; i++) {
                uint256 j1 = (i * t) << 1;
                uint256 j2 = j1 + t - 1;
                uint256 S = psi_rev[m + i];

                for (uint256 j = j1; j <= j2; j++) {
                    uint256 U = a[j];
                    uint256 V = mulmod(a[j + t], S, Q);
                    a[j] = addmod(U, V, Q);
                    a[j + t] = addmod(U, Q - V, Q);
                }
            }
            m = m << 1;
        }
        return a;
    }

    // NTT обратное
    function intt(uint256[] memory a) internal view returns (uint256[] memory) {
        uint256 t = 1;
        uint256 m = a.length;
        uint256[256] memory psi_inv_rev = NTTConstants(CONSTANTS_ADDR)
            .getPsiInvRev();
        while (m > 1) {
            uint256 j1 = 0;
            uint256 h = m >> 1;
            for (uint256 i = 0; i < h; i++) {
                uint256 j2 = j1 + t - 1;
                uint256 S = psi_inv_rev[h + i];
                for (uint256 j = j1; j <= j2; j++) {
                    uint256 U = a[j];
                    uint256 V = a[j + t];
                    a[j] = addmod(U, V, Q);
                    a[j + t] = mulmod(addmod(U, Q - V, Q), S, Q);
                }
                j1 = j1 + (t << 1);
            }
            t = t << 1;
            m = m >> 1;
        }

        // Умножаем на N^-1 mod Q
        for (uint256 i = 0; i < a.length; i++) {
            a[i] = mulmod(a[i], N_INV, Q);
        }
        return a;
    }

    // Умножение двух полиномов в стандартном представлении
    function mul(
        uint256[] memory a,
        uint256[] memory b
    ) public view returns (uint256[] memory) {
        require(a.length == N && b.length == N, "Length must be N");
        // Копируем массивы, чтобы не изменять входные
        uint256[] memory a_ntt = new uint256[](N);
        uint256[] memory b_ntt = new uint256[](N);
        for (uint256 i = 0; i < N; i++) {
            a_ntt[i] = a[i];
            b_ntt[i] = b[i];
        }
        a_ntt = ntt(a_ntt);
        b_ntt = ntt(b_ntt);
        for (uint256 i = 0; i < N; i++) {
            a_ntt[i] = mulmod(a_ntt[i], b_ntt[i], Q);
        }
        return intt(a_ntt);
    }
} //end of contract
/**
 *
 */
/*                                                                  END OF CONTRACT                                                                                     */
/**
 *
 */
