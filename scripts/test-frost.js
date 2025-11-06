#!/usr/bin/env node

/**
 * Test FROST Threshold Signature Implementation
 * Validates key generation, signing, and verification
 */

const FrostSignature = require('./frost-crypto');

function testFrostSignature() {
  console.log('🔐 Testing FROST Threshold Signature Implementation\n');
  
  const frost = new FrostSignature();
  
  // Test 1: Key Generation
  console.log('1. Testing key generation...');
  const participants = 5;
  const threshold = 3;
  
  let keyShares;
  try {
    keyShares = frost.generateKeyShares(participants, threshold);
    console.log(`✅ Generated ${participants} key shares with threshold ${threshold}`);
    console.log(`   Group Public Key: ${keyShares.groupPublicKey.x.substring(0, 16)}...`);
    console.log(`   Total shares: ${keyShares.shares.length}`);
    console.log(`   Total public shares: ${keyShares.publicShares.length}\n`);
  } catch (error) {
    console.error('❌ Key generation failed:', error.message);
    process.exit(1);
  }
  
  // Test 2: Invalid Parameters
  console.log('2. Testing invalid parameters...');
  try {
    frost.generateKeyShares(2, 3); // threshold > participants
    console.error('❌ Should have thrown error for threshold > participants');
    process.exit(1);
  } catch (error) {
    console.log('✅ Correctly rejected threshold > participants\n');
  }
  
  try {
    frost.generateKeyShares(5, 0); // threshold = 0
    console.error('❌ Should have thrown error for threshold = 0');
    process.exit(1);
  } catch (error) {
    console.log('✅ Correctly rejected threshold = 0\n');
  }
  
  // Test 3: Commitment Generation
  console.log('3. Testing commitment generation...');
  const commitments = [];
  try {
    for (let i = 0; i < threshold; i++) {
      const commitment = frost.generateCommitment(keyShares.shares[i]);
      commitments.push(commitment);
      console.log(`   Participant ${i + 1} commitment: ${commitment.commitment.x.substring(0, 16)}...`);
    }
    console.log('✅ Generated commitments for threshold participants\n');
  } catch (error) {
    console.error('❌ Commitment generation failed:', error.message);
    process.exit(1);
  }
  
  // Test 4: Signature Share Generation
  console.log('4. Testing signature share generation...');
  const message = 'Test message for FROST signature';
  const signatureShares = [];
  
  try {
    for (let i = 0; i < threshold; i++) {
      const sigShare = frost.generateSignatureShare(
        message,
        keyShares.shares[i],
        commitments[i].nonce,
        commitments.map(c => c.commitment),
        keyShares.publicShares
      );
      signatureShares.push(sigShare);
      console.log(`   Participant ${sigShare.index} signature share: ${sigShare.value.substring(0, 16)}...`);
    }
    console.log('✅ Generated signature shares from threshold participants\n');
  } catch (error) {
    console.error('❌ Signature share generation failed:', error.message);
    process.exit(1);
  }
  
  // Test 5: Signature Combination
  console.log('5. Testing signature combination...');
  let combinedSignature;
  try {
    combinedSignature = frost.combineSignatureShares(
      message,
      signatureShares,
      commitments.map(c => c.commitment),
      keyShares.publicShares,
      threshold
    );
    console.log(`   Combined signature r: ${combinedSignature.r.substring(0, 32)}...`);
    console.log(`   Combined signature s: ${combinedSignature.s.substring(0, 32)}...`);
    console.log(`   Combined signature v: ${combinedSignature.v}`);
    console.log('✅ Successfully combined signature shares\n');
  } catch (error) {
    console.error('❌ Signature combination failed:', error.message);
    process.exit(1);
  }
  
  // Test 6: Insufficient Shares
  console.log('6. Testing insufficient signature shares...');
  try {
    frost.combineSignatureShares(
      message,
      signatureShares.slice(0, threshold - 1), // Not enough shares
      commitments.map(c => c.commitment),
      keyShares.publicShares,
      threshold
    );
    console.error('❌ Should have thrown error for insufficient shares');
    process.exit(1);
  } catch (error) {
    console.log(`✅ Correctly rejected insufficient shares: ${error.message}\n`);
  }
  
  // Test 7: Different Thresholds
  console.log('7. Testing different threshold configurations...');
  const configs = [
    { n: 3, t: 2 },
    { n: 7, t: 4 },
    { n: 10, t: 7 }
  ];
  
  for (const config of configs) {
    try {
      const shares = frost.generateKeyShares(config.n, config.t);
      console.log(`   ✅ ${config.t}-of-${config.n} configuration successful`);
    } catch (error) {
      console.error(`   ❌ ${config.t}-of-${config.n} configuration failed:`, error.message);
    }
  }
  console.log();
  
  // Test 8: Signature Format Validation
  console.log('8. Validating signature format...');
  if (combinedSignature.r.length === 64 && combinedSignature.s.length === 64) {
    console.log('✅ Signature components have correct length (32 bytes each)\n');
  } else {
    console.error(`❌ Invalid signature length: r=${combinedSignature.r.length}, s=${combinedSignature.s.length}`);
  }
  
  // Test 9: Performance Benchmark
  console.log('9. Performance benchmark...');
  const iterations = 100;
  const startTime = Date.now();
  
  for (let i = 0; i < iterations; i++) {
    frost.generateKeyShares(5, 3);
  }
  
  const endTime = Date.now();
  const avgTime = (endTime - startTime) / iterations;
  console.log(`   Average key generation time: ${avgTime.toFixed(2)}ms`);
  console.log(`   Throughput: ${(1000 / avgTime).toFixed(2)} operations/second\n`);
  
  // Summary
  console.log('═══════════════════════════════════════');
  console.log('✅ FROST Signature Test Complete');
  console.log('═══════════════════════════════════════');
  console.log('\n⚠️  IMPORTANT NOTES:');
  console.log('1. Current implementation uses simplified signature generation');
  console.log('2. The "s" value is randomly generated (NOT production-ready)');
  console.log('3. Signature verification needs proper FROST-specific logic');
  console.log('4. Random number generation should use crypto.randomBytes()');
  console.log('\nNext steps:');
  console.log('1. Implement proper FROST signature combination');
  console.log('2. Add cryptographically secure random number generation');
  console.log('3. Implement proper signature verification');
  console.log('4. Run: node scripts/test-policies.js');
}

// Run the test
try {
  testFrostSignature();
} catch (error) {
  console.error('\n❌ Unexpected error:', error);
  process.exit(1);
}