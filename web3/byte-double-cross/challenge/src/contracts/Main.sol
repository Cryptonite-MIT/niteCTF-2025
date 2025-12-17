// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ChunkedFlag {
    bytes32[] public solutionHashes;
    address public owner;

    constructor() {
        owner = msg.sender;
        solutionHashes = [bytes32(0xf59964cd0c25442208c8d0135bf938cf10dee456234ac55bccafac25e7f16234),
        bytes32(0xa12f9f56c9d0067235de6a2fd821977bacc4d5ed6a9d9f7e38d643143f855688),
        bytes32(0x3486d083d2655b16f836dcf07114c4a738727c9481b620cdf2db59cd5acfe372),
        bytes32(0x2dfb14ffa4d2fe750d6e28014c3013793b22e122190a335a308f0d330143da3d),
        bytes32(0xd62d22652789151588d2d49bcd0d20a41e2ba09f319f6cf84bc712ea45a215ef),
        bytes32(0x6cf18571f33a226462303a6ae09be5de3c725b724bf623b5691dcb60651ee136),
        bytes32(0x2b86ca86c8cfc8aa383afc78aa91ab265b174071d300c720e178264d2f647a42),
        bytes32(0xe9d5b7877c45245ca46dc5975dc6b577baa951b05f59a8e7b87468bfad4a956d)];
    }

    function checkFlag(bytes32[] memory parts) public view returns (bool) {
        require(parts.length == solutionHashes.length, "Wrong number of chunks");

        for (uint i = 0; i < parts.length; i++) {
            bytes32 calculatedHash = keccak256(abi.encodePacked(parts[i], owner));
            require(calculatedHash == solutionHashes[i], "Invalid Chunk");
        }

        return true;
    }
}
