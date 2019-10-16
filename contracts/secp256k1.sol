pragma solidity >=0.4.0 <0.6.0;

import "./EllipticCurve.sol";


/**
 * @title Secp256k1 Elliptic Curve
 * @notice Example of particularization of Elliptic Curve for secp256k1 curve
 * @author Witnet Foundation
 */
library secp256k1 {

  uint256 constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  uint256 constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
  uint256 constant AA = 0;
  uint256 constant BB = 7;
  uint256 constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
  uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  /// @dev Public Key derivation from private key
  /// @param privKey The private key
  /// @return (qx, qy) The Public Key
  function derivePubKey(uint256 privKey) public pure returns(uint256 qx, uint256 qy) {
    (qx, qy) = EllipticCurve.ecMul(
      privKey,
      GX,
      GY,
      AA,
      PP
    );
  }

  function ecMultG(uint256 s) public pure returns(uint256 qx, uint256 qy) {
    (qx, qy) = EllipticCurve.ecMul(
      s,
      GX,
      GY,
      AA,
      PP
    );
  }

  function ecMult(uint256[2] memory keyImage, uint256 s) public pure returns(uint256 qx, uint256 qy) {
    (qx, qy) = EllipticCurve.ecMul(
      s,
      keyImage[0],
      keyImage[1],
      AA,
      PP
    );
  }

  function ecAddd(uint256[2] memory x, uint256[2] memory y) public pure returns(uint256 qx, uint256 qy) {
    (qx, qy) = EllipticCurve.ecAdd(
      x[0],
      x[1],
      y[0],
      y[1],
      AA,
      PP
    );
  }

  function map_curve(uint8 prefix, uint256 x) public pure returns(uint256 beta, uint256 y3) {
    (beta, y3) = EllipticCurve.deriveY(
      prefix,
      x, 
      AA, 
      BB, 
      PP
    );
    
  }

  function onCurveBeta(uint256 beta, uint256 y) public pure returns(bool) {
    return beta == mulmod(y, y, PP);
  }

  function addmodn(uint256 x, uint256 n) public pure returns (uint256) {
    return addmod(x, n, N);
  }

  function modn(uint256 x) public pure returns (uint256) {
    return x % N;
  }

  function onCurve(uint256 x, uint256 y) public pure returns (bool b) {
    b = EllipticCurve.isOnCurve(
      x,
      y,
      AA,
      BB,
      PP
    );
 
  }










}