// FROST Threshold Signature implementation
const { createHash, randomBytes } = require('crypto');
const elliptic = require('elliptic');
const BN = require('bn.js');

// Initialize elliptic curve (secp256k1 is used by Ethereum)
const ec = new elliptic.ec('secp256k1');

class FrostSignature {
  constructor() {
    this.curve = ec;
  }

  // Generate key shares for n participants with threshold t
  generateKeyShares(n, t) {
    if (t > n) throw new Error('Threshold cannot exceed total participants');
    if (t < 1) throw new Error('Threshold must be at least 1');

    // Generate polynomial coefficients [a_0, a_1, ..., a_{t-1}]
    // where a_0 is the secret key
    const coefficients = [];
    for (let i = 0; i < t; i++) {
      coefficients.push(new BN(this._generateRandomPrivateKey(), 16));
    }

    const shares = [];
    const publicShares = [];

    // Calculate shares for each participant
    for (let i = 1; i <= n; i++) {
      const x = new BN(i);
      let share = new BN(0);

      // Evaluate polynomial at x: f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
      for (let j = 0; j < t; j++) {
        let term = coefficients[j].mul(x.pow(new BN(j))).mod(ec.curve.n);
        share = share.add(term).mod(ec.curve.n);
      }

      shares.push({ index: i, value: share.toString('hex') });

      // Generate public share (g^{share})
      const pubPoint = ec.g.mul(share);
      publicShares.push({
        index: i,
        x: pubPoint.getX().toString('hex'),
        y: pubPoint.getY().toString('hex')
      });
    }

    // Calculate group public key (g^{a_0})
    const groupPublicKey = ec.g.mul(coefficients[0]);

    return {
      shares,                 // Private shares for each participant
      publicShares,           // Public shares for verification
      groupPublicKey: {       // The group's public key
        x: groupPublicKey.getX().toString('hex'),
        y: groupPublicKey.getY().toString('hex')
      },
      threshold: t,
      total: n
    };
  }

  // Generate commitment for the preprocessing phase
  generateCommitment(privateShare) {
    // Generate one-time secret nonce
    const nonce = new BN(this._generateRandomPrivateKey(), 16);
    
    // Calculate commitment D = g^nonce
    const commitment = ec.g.mul(nonce);
    
    return {
      nonce: nonce.toString('hex'),
      commitment: {
        x: commitment.getX().toString('hex'),
        y: commitment.getY().toString('hex')
      }
    };
  }

  // Generate signature share during the signing phase
  generateSignatureShare(message, privateShare, nonce, commitments, participants) {
    const messageHash = this._hashMessage(message);
    const msgBN = new BN(messageHash, 16);
    
    // Participant's private key share
    const privateKeyShare = new BN(privateShare.value, 16);
    
    // Calculate binding factor
    const bindingFactor = this._calculateBindingFactor(messageHash, commitments);
    
    // Convert nonce to BN
    const nonceBN = new BN(nonce, 16);
    
    // Calculate signature share: z_i = nonce_i + c * privateKeyShare_i
    const c = new BN(bindingFactor, 16);
    const signatureShare = nonceBN.add(c.mul(privateKeyShare).mod(ec.curve.n)).mod(ec.curve.n);
    
    return {
      index: privateShare.index,
      value: signatureShare.toString('hex')
    };
  }

  // Combine signature shares to create the threshold signature
  combineSignatureShares(message, signatureShares, commitments, publicShares, threshold) {
    if (signatureShares.length < threshold) {
      throw new Error(`Not enough signature shares. Need ${threshold}, got ${signatureShares.length}`);
    }
    
    const messageHash = this._hashMessage(message);
    const bindingFactor = this._calculateBindingFactor(messageHash, commitments);
    
    // Calculate Lagrange coefficients
    const indices = signatureShares.map(share => share.index);
    const lagrangeCoefficients = this._calculateLagrangeCoefficients(indices);
    
    // Combine signature shares using Lagrange interpolation
    let combinedSignature = new BN(0);
    
    for (let i = 0; i < signatureShares.length; i++) {
      const share = new BN(signatureShares[i].value, 16);
      const lagrange = new BN(lagrangeCoefficients[i], 16);
      
      combinedSignature = combinedSignature.add(share.mul(lagrange).mod(ec.curve.n)).mod(ec.curve.n);
    }
    
    // Convert combined signature to Ethereum signature format (r, s, v)
    const r = combinedSignature.toString('hex').padStart(64, '0');
    
    // For simplicity, we're using a dummy s value and v value
    // In a real implementation, these would be properly calculated
    const s = new BN(this._generateRandomPrivateKey(), 16).toString('hex').padStart(64, '0');
    const v = 27; // Either 27 or 28 for Ethereum
    
    return {
      r,
      s,
      v,
      combined: combinedSignature.toString('hex')
    };
  }

  // Verify a FROST threshold signature
  verifySignature(message, signature, groupPublicKey) {
    try {
      const messageHash = this._hashMessage(message);
      
      // Convert signature to point on curve
      const sigPoint = {
        r: new BN(signature.r, 16),
        s: new BN(signature.s, 16)
      };
      
      // Convert group public key to curve point
      const pubKeyPoint = ec.keyFromPublic({
        x: groupPublicKey.x,
        y: groupPublicKey.y
      });
      
      // Verify using elliptic.js
      const msgBN = new BN(messageHash, 16);
      return ec.verify(msgBN, sigPoint, pubKeyPoint);
    } catch (error) {
      console.error("Signature verification error:", error);
      return false;
    }
  }

  // Helper: Calculate Lagrange coefficients for interpolation
  _calculateLagrangeCoefficients(indices) {
    const coefficients = [];
    
    for (let i = 0; i < indices.length; i++) {
      let coeff = new BN(1);
      const xi = new BN(indices[i]);
      
      for (let j = 0; j < indices.length; j++) {
        if (i !== j) {
          const xj = new BN(indices[j]);
          const num = new BN(0).sub(xj).mod(ec.curve.n); // -xj
          const denom = xi.sub(xj).mod(ec.curve.n); // xi - xj
          const denomInv = denom.invm(ec.curve.n); // (xi - xj)^-1
          
          coeff = coeff.mul(num).mul(denomInv).mod(ec.curve.n);
        }
      }
      
      coefficients.push(coeff.toString('hex'));
    }
    
    return coefficients;
  }

  // Helper: Calculate binding factor (challenge)
  _calculateBindingFactor(messageHash, commitments) {
    let commitmentString = '';
    for (const commitment of commitments) {
      commitmentString += commitment.x + commitment.y;
    }
    
    const bindingFactorInput = messageHash + commitmentString;
    return createHash('sha256').update(bindingFactorInput).digest('hex');
  }

  // Helper: Hash message for signing
  _hashMessage(message) {
    return createHash('sha256').update(message).digest('hex');
  }

  // Helper: Generate cryptographically secure random private key
  _generateRandomPrivateKey() {
    // Generate a cryptographically secure random 32-byte private key
    let privateKey;
    
    do {
      // Use crypto.randomBytes for cryptographically secure random number generation
      const randomBytesBuffer = randomBytes(32);
      privateKey = randomBytesBuffer.toString('hex');
    } while (new BN(privateKey, 16).gte(ec.curve.n));
    
    return privateKey;
  }
}

module.exports = FrostSignature;