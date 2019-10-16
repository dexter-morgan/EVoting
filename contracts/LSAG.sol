pragma solidity >=0.4.0 <0.6.0;

// import "./AltBn128.sol";
import "./secp256k1.sol";

/*
Linkable Spontaneous Anonymous Groups

https://eprint.iacr.org/2004/027.pdf
*/

library LSAG {
    // abi.encodePacked is the "concat" or "serialization"
    // of all supplied arguments into one long bytes value
    // i.e. abi.encodePacked :: [a] -> bytes

    /**
    * Converts an integer to an elliptic curve point
    */
    function intToPoint(uint256 _x) public view
        returns (uint256[2] memory)
    {
        uint256 x = _x;
        uint256 y;
        uint256 beta;
        uint8 prefix = 0x0;

        if (_x%2 == 0) {
            prefix = 0x02;
        }
        if (_x%2 == 1) {
            prefix = 0x03;
        }

        while (true) {

            (beta, y) = secp256k1.map_curve(prefix, x);

            if (secp256k1.onCurve(x, y)) {
                return [x, y];
            }

            x = secp256k1.addmodn(x, 1);
        }
    }

    /**
    * Returns an integer representation of the hash
    * of the input
    */
    function H1(bytes memory b) public pure
        returns (uint256)
    {   
        uint256 a = 11631197716381341491910650601086533899062258680921704624436296724004857123675;
        return secp256k1.modn(uint256(sha256(b)));
    }

    /**
    * Returns elliptic curve point of the integer representation
    * of the hash of the input
    */
    function H2(bytes memory b) public view
        returns (uint256[2] memory)
    {

        return intToPoint(H1(b));
    }

    /**
    * Helper function to calculate Z1
    * Avoids stack too deep problem
    */
    function ringCalcZ1(
        uint256[2] memory pubKey,
        uint256 c,
        uint256 s
    ) public view
        returns (uint256[2] memory)
    {

        // return AltBn128.ecAdd(
        //     AltBn128.ecMulG(s),
        //     AltBn128.ecMul(pubKey, c)
        // );

        uint256[2] memory output;
        uint256[2] memory p1;
        uint256[2] memory p2;
        uint256 x;
        uint256 y; 

        (x, y) = secp256k1.ecMultG(s);

        p1[0] = x;
        p1[1] = y;

        (x, y) = secp256k1.ecMult(pubKey, c);

        p2[0] = x;
        p2[1] = y;

        (x, y) = secp256k1.ecAddd(
            p1,
            p2
        );

        output[0] = x;
        output[1] = y;
        return output;
    }

    /**
    * Helper function to calculate Z2
    * Avoids stack too deep problem
    */
    function ringCalcZ2(
        uint256[2] memory keyImage,
        uint256[2] memory h,
        uint256 s,
        uint256 c
    ) public view
        returns (uint256[2] memory)
    {
        // return AltBn128.ecAdd(
        //     AltBn128.ecMul(h, s),
        //     AltBn128.ecMul(keyImage, c)
        // );

        uint256[2] memory output;
        uint256[2] memory p1;
        uint256[2] memory p2;
        uint256 x;
        uint256 y; 

        (x, y) = secp256k1.ecMult(h, s);

        p1[0] = x;
        p1[1] = y;

        (x, y) = secp256k1.ecMult(keyImage, c);

        p2[0] = x;
        p2[1] = y;

        (x, y) = secp256k1.ecAddd(
            p1,
            p2
        );

        output[0] = x;
        output[1] = y;
        return output;
    }


    /**
    * Verifies the ring signature
    * Section 4.2 of the paper https://eprint.iacr.org/2004/027.pdf
    */
    function verify(
        bytes memory message,
        uint256 c0,
        uint256[2] memory keyImage,
        uint256[] memory s,
        uint256[2][] memory publicKeys
    ) public view
        returns (bool)
    {
        
        
        require(publicKeys.length >= 2, "Signature size too small");
        require(publicKeys.length == s.length, "Signature sizes do not match!");


        uint256 c = c0;
        uint256 i = 0;

        // Step 1
        // Extract out public key bytes
        bytes memory hBytes = "";

        for (i = 0; i < publicKeys.length; i++) {
            hBytes = abi.encodePacked(
                hBytes,
                publicKeys[i]
            );
        }


        uint256[2] memory h = H2(hBytes);

        // require(h[0] ==106245785169166674832827933205895298349539914377793708839139737261608903456172, "H[0] is not matching");
        // require(h[1] == 38130597350437976482118320406716909458312114499366885177464997577442444961143, "H[1] is not matching");


        // Step 2
        uint256[2] memory z_1;
        uint256[2] memory z_2;


        for (i = 0; i < publicKeys.length; i++) {


            z_1 = ringCalcZ1(publicKeys[i], c, s[i]);
            z_2 = ringCalcZ2(keyImage, h, s[i], c);
            // require(z_1[0] == 104603062327150847596075863885237206448711583172763894617559229948636949816387, "z_1[0] me problem hai");
            // require(z_1[1] == 3877022914943913174973231854694363839599317059260525512126388493689905288930, "z_1[1] me problem hai");
            // require(z_2[0] == 25157251625505657634097849792771000312472027419867594537390547422728421981871, "z_2[0] me problem hai");
            // require(z_2[1] == 69948776311331987906694682752320754045742553606829709747780937321352532856962, "z_2[1] me problem hai");



            if (i != publicKeys.length - 1) {
                c = H1(
                    abi.encodePacked(
                        hBytes,
                        keyImage,
                        message,
                        z_1,
                        z_2
                    )
                );

            }
        }

        return c0 == H1(
            abi.encodePacked(
                hBytes,
                keyImage,
                message,
                z_1,
                z_2
            )
        );

    }
}