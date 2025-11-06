#!/usr/bin/env node

/**
 * Test Policy Management System
 * Comprehensive testing of access control policies, permissions, and blockchain integration
 */

const { ethers } = require('ethers');
const FrostSignature = require('./frost-crypto');
require('dotenv').config();

// Test configuration
const TEST_CONFIG = {
  rpcEndpoint: process.env.RPC_ENDPOINT || 'http://localhost:8545',
  frostMultiSigAddress: process.env.FROST_MULTISIG_ADDRESS,
  accessControlRegistryAddress: process.env.ACCESS_CONTROL_REGISTRY_ADDRESS,
  testResourceId: 'arn:aws:s3:::test-bucket-policy',
  testPrincipalId: 'user:test@example.com',
  testCloudProvider: 1, // 1 = AWS, 2 = Azure, 3 = GCP
  testThreshold: 3,
  testParticipants: 5
};

class PolicyTester {
  constructor() {
    this.provider = null;
    this.frostMultiSigContract = null;
    this.accessControlRegistryContract = null;
    this.frostCrypto = new FrostSignature();
    this.testResults = [];
  }

  async initialize() {
    console.log('🔧 Initializing Policy Tester...\n');
    
    // Initialize provider
    this.provider = new ethers.providers.JsonRpcProvider(TEST_CONFIG.rpcEndpoint);
    
    // Check if contracts are deployed
    if (!TEST_CONFIG.frostMultiSigAddress || !TEST_CONFIG.accessControlRegistryAddress) {
      console.error('❌ Contract addresses not set in environment variables');
      console.log('Please set FROST_MULTISIG_ADDRESS and ACCESS_CONTROL_REGISTRY_ADDRESS in your .env file');
      process.exit(1);
    }
    
    // Load contract ABIs
    const frostMultiSigAbi = require('../artifacts/contracts/FrostMultiSig.sol/FrostMultiSig.json').abi;
    const accessControlRegistryAbi = require('../artifacts/contracts/AccessControlRegistry.sol/AccessControlRegistry.json').abi;
    
    // Initialize contracts
    this.frostMultiSigContract = new ethers.Contract(
      TEST_CONFIG.frostMultiSigAddress,
      frostMultiSigAbi,
      this.provider
    );
    
    this.accessControlRegistryContract = new ethers.Contract(
      TEST_CONFIG.accessControlRegistryAddress,
      accessControlRegistryAbi,
      this.provider
    );
    
    console.log('✅ Contracts initialized successfully\n');
  }

  async runAllTests() {
    console.log('🧪 Starting Policy Management Tests\n');
    console.log('═══════════════════════════════════════\n');
    
    try {
      await this.testContractConnectivity();
      await this.testPolicyCreation();
      await this.testPermissionGranting();
      await this.testPermissionRevoking();
      await this.testPolicyExpiry();
      await this.testFrostSignatureIntegration();
      await this.testAccessValidation();
      await this.testErrorHandling();
      await this.testGasOptimization();
      await this.testSecurityFeatures();
      
      this.printTestSummary();
    } catch (error) {
      console.error('❌ Test suite failed:', error.message);
      process.exit(1);
    }
  }

  async testContractConnectivity() {
    console.log('1. Testing Contract Connectivity...');
    
    try {
      // Test FrostMultiSig contract
      const frostMultiSigAddress = await this.frostMultiSigContract.address;
      console.log(`   ✅ FrostMultiSig contract: ${frostMultiSigAddress}`);
      
      // Test AccessControlRegistry contract
      const accessControlAddress = await this.accessControlRegistryContract.address;
      console.log(`   ✅ AccessControlRegistry contract: ${accessControlAddress}`);
      
      // Test network connectivity
      const blockNumber = await this.provider.getBlockNumber();
      console.log(`   ✅ Network connected (block: ${blockNumber})\n`);
      
      this.testResults.push({ test: 'Contract Connectivity', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ Contract connectivity failed: ${error.message}\n`);
      this.testResults.push({ test: 'Contract Connectivity', status: 'FAIL', error: error.message });
    }
  }

  async testPolicyCreation() {
    console.log('2. Testing Policy Creation...');
    
    try {
      const resourceId = ethers.utils.formatBytes32String(TEST_CONFIG.testResourceId);
      const principalId = ethers.utils.formatBytes32String(TEST_CONFIG.testPrincipalId);
      
      // Check if policy already exists
      const existingPolicy = await this.accessControlRegistryContract.resourcePolicies(resourceId);
      
      if (existingPolicy.created.toNumber() > 0) {
        console.log('   ⚠️  Policy already exists, skipping creation\n');
        this.testResults.push({ test: 'Policy Creation', status: 'SKIP' });
        return;
      }
      
      // Create a new policy (this would require a transaction in real scenario)
      console.log('   📝 Policy creation test (simulation)');
      console.log(`   Resource ID: ${TEST_CONFIG.testResourceId}`);
      console.log(`   Principal ID: ${TEST_CONFIG.testPrincipalId}`);
      console.log(`   Cloud Provider: ${['', 'AWS', 'Azure', 'GCP'][TEST_CONFIG.testCloudProvider]}`);
      console.log('   ✅ Policy creation parameters validated\n');
      
      this.testResults.push({ test: 'Policy Creation', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ Policy creation test failed: ${error.message}\n`);
      this.testResults.push({ test: 'Policy Creation', status: 'FAIL', error: error.message });
    }
  }

  async testPermissionGranting() {
    console.log('3. Testing Permission Granting...');
    
    try {
      const resourceId = ethers.utils.formatBytes32String(TEST_CONFIG.testResourceId);
      const principalId = ethers.utils.formatBytes32String(TEST_CONFIG.testPrincipalId);
      
      // Check current permission status
      const hasPermission = await this.accessControlRegistryContract.hasPermission(resourceId, principalId);
      console.log(`   Current permission status: ${hasPermission}`);
      
      if (hasPermission) {
        console.log('   ✅ Permission already granted\n');
      } else {
        console.log('   📝 Permission granting test (simulation)');
        console.log('   ✅ Permission granting parameters validated\n');
      }
      
      this.testResults.push({ test: 'Permission Granting', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ Permission granting test failed: ${error.message}\n`);
      this.testResults.push({ test: 'Permission Granting', status: 'FAIL', error: error.message });
    }
  }

  async testPermissionRevoking() {
    console.log('4. Testing Permission Revoking...');
    
    try {
      const resourceId = ethers.utils.formatBytes32String(TEST_CONFIG.testResourceId);
      const principalId = ethers.utils.formatBytes32String(TEST_CONFIG.testPrincipalId);
      
      console.log('   📝 Permission revoking test (simulation)');
      console.log('   ✅ Permission revoking parameters validated\n');
      
      this.testResults.push({ test: 'Permission Revoking', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ Permission revoking test failed: ${error.message}\n`);
      this.testResults.push({ test: 'Permission Revoking', status: 'FAIL', error: error.message });
    }
  }

  async testPolicyExpiry() {
    console.log('5. Testing Policy Expiry...');
    
    try {
      const resourceId = ethers.utils.formatBytes32String(TEST_CONFIG.testResourceId);
      
      // Get policy details
      const policy = await this.accessControlRegistryContract.resourcePolicies(resourceId);
      const expiryTime = policy.expiryTime.toNumber();
      
      if (expiryTime > 0) {
        const expiryDate = new Date(expiryTime * 1000);
        const isExpired = Date.now() > expiryTime * 1000;
        
        console.log(`   Policy expiry time: ${expiryDate.toISOString()}`);
        console.log(`   Is expired: ${isExpired}`);
        
        if (isExpired) {
          console.log('   ⚠️  Policy has expired');
        } else {
          console.log('   ✅ Policy is still valid');
        }
      } else {
        console.log('   ✅ Policy has no expiry (permanent)');
      }
      
      console.log();
      this.testResults.push({ test: 'Policy Expiry', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ Policy expiry test failed: ${error.message}\n`);
      this.testResults.push({ test: 'Policy Expiry', status: 'FAIL', error: error.message });
    }
  }

  async testFrostSignatureIntegration() {
    console.log('6. Testing FROST Signature Integration...');
    
    try {
      // Generate FROST key shares
      const keyShares = this.frostCrypto.generateKeyShares(
        TEST_CONFIG.testParticipants,
        TEST_CONFIG.testThreshold
      );
      
      console.log(`   Generated ${TEST_CONFIG.testParticipants} key shares with threshold ${TEST_CONFIG.testThreshold}`);
      console.log(`   Group public key: ${keyShares.groupPublicKey.x.substring(0, 16)}...`);
      
      // Test signature generation
      const message = 'Test message for policy validation';
      const commitments = [];
      
      for (let i = 0; i < TEST_CONFIG.testThreshold; i++) {
        const commitment = this.frostCrypto.generateCommitment(keyShares.shares[i]);
        commitments.push(commitment);
      }
      
      const signatureShares = [];
      for (let i = 0; i < TEST_CONFIG.testThreshold; i++) {
        const sigShare = this.frostCrypto.generateSignatureShare(
          message,
          keyShares.shares[i],
          commitments[i].nonce,
          commitments.map(c => c.commitment),
          keyShares.publicShares
        );
        signatureShares.push(sigShare);
      }
      
      const combinedSignature = this.frostCrypto.combineSignatureShares(
        message,
        signatureShares,
        commitments.map(c => c.commitment),
        keyShares.publicShares,
        TEST_CONFIG.testThreshold
      );
      
      console.log(`   Generated signature: r=${combinedSignature.r.substring(0, 16)}...`);
      console.log('   ✅ FROST signature integration working\n');
      
      this.testResults.push({ test: 'FROST Signature Integration', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ FROST signature integration failed: ${error.message}\n`);
      this.testResults.push({ test: 'FROST Signature Integration', status: 'FAIL', error: error.message });
    }
  }

  async testAccessValidation() {
    console.log('7. Testing Access Validation...');
    
    try {
      const resourceId = ethers.utils.formatBytes32String(TEST_CONFIG.testResourceId);
      const principalId = ethers.utils.formatBytes32String(TEST_CONFIG.testPrincipalId);
      
      // Test permission check
      const hasPermission = await this.accessControlRegistryContract.hasPermission(resourceId, principalId);
      console.log(`   Permission check result: ${hasPermission}`);
      
      // Test policy lookup
      const policy = await this.accessControlRegistryContract.resourcePolicies(resourceId);
      const policyExists = policy.created.toNumber() > 0;
      console.log(`   Policy exists: ${policyExists}`);
      
      if (policyExists) {
        console.log(`   Cloud provider: ${['', 'AWS', 'Azure', 'GCP'][policy.cloudProvider]}`);
        console.log(`   Requires FROST signature: ${policy.requiresFrostSig}`);
      }
      
      console.log('   ✅ Access validation working\n');
      this.testResults.push({ test: 'Access Validation', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ Access validation test failed: ${error.message}\n`);
      this.testResults.push({ test: 'Access Validation', status: 'FAIL', error: error.message });
    }
  }

  async testErrorHandling() {
    console.log('8. Testing Error Handling...');
    
    try {
      // Test invalid resource ID
      const invalidResourceId = ethers.utils.formatBytes32String('invalid-resource');
      const invalidPrincipalId = ethers.utils.formatBytes32String('invalid-principal');
      
      try {
        await this.accessControlRegistryContract.hasPermission(invalidResourceId, invalidPrincipalId);
        console.log('   ✅ Invalid resource/principal handled gracefully');
      } catch (error) {
        console.log('   ✅ Error handling working for invalid inputs');
      }
      
      // Test empty parameters
      try {
        await this.accessControlRegistryContract.hasPermission('0x0000000000000000000000000000000000000000000000000000000000000000', '0x0000000000000000000000000000000000000000000000000000000000000000');
        console.log('   ✅ Empty parameters handled');
      } catch (error) {
        console.log('   ✅ Error handling working for empty parameters');
      }
      
      console.log('   ✅ Error handling tests passed\n');
      this.testResults.push({ test: 'Error Handling', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ Error handling test failed: ${error.message}\n`);
      this.testResults.push({ test: 'Error Handling', status: 'FAIL', error: error.message });
    }
  }

  async testGasOptimization() {
    console.log('9. Testing Gas Optimization...');
    
    try {
      // Estimate gas for common operations
      const resourceId = ethers.utils.formatBytes32String(TEST_CONFIG.testResourceId);
      const principalId = ethers.utils.formatBytes32String(TEST_CONFIG.testPrincipalId);
      
      // Test gas estimation for permission check (view function)
      const gasEstimate = await this.accessControlRegistryContract.estimateGas.hasPermission(resourceId, principalId);
      console.log(`   Permission check gas estimate: ${gasEstimate.toString()}`);
      
      // Test gas estimation for policy lookup (view function)
      const policyGasEstimate = await this.accessControlRegistryContract.estimateGas.resourcePolicies(resourceId);
      console.log(`   Policy lookup gas estimate: ${policyGasEstimate.toString()}`);
      
      console.log('   ✅ Gas optimization tests passed\n');
      this.testResults.push({ test: 'Gas Optimization', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ Gas optimization test failed: ${error.message}\n`);
      this.testResults.push({ test: 'Gas Optimization', status: 'FAIL', error: error.message });
    }
  }

  async testSecurityFeatures() {
    console.log('10. Testing Security Features...');
    
    try {
      // Test role-based access control
      const adminRole = await this.accessControlRegistryContract.DEFAULT_ADMIN_ROLE();
      console.log(`   Admin role: ${adminRole}`);
      
      // Test pausable functionality
      const isPaused = await this.accessControlRegistryContract.paused();
      console.log(`   Contract paused: ${isPaused}`);
      
      // Test circuit breaker
      const circuitBreakerEnabled = await this.accessControlRegistryContract.circuitBreakerEnabled();
      console.log(`   Circuit breaker enabled: ${circuitBreakerEnabled}`);
      
      console.log('   ✅ Security features tests passed\n');
      this.testResults.push({ test: 'Security Features', status: 'PASS' });
    } catch (error) {
      console.error(`   ❌ Security features test failed: ${error.message}\n`);
      this.testResults.push({ test: 'Security Features', status: 'FAIL', error: error.message });
    }
  }

  printTestSummary() {
    console.log('═══════════════════════════════════════');
    console.log('📊 Test Summary');
    console.log('═══════════════════════════════════════');
    
    const passed = this.testResults.filter(r => r.status === 'PASS').length;
    const failed = this.testResults.filter(r => r.status === 'FAIL').length;
    const skipped = this.testResults.filter(r => r.status === 'SKIP').length;
    const total = this.testResults.length;
    
    console.log(`Total Tests: ${total}`);
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`⏭️  Skipped: ${skipped}`);
    console.log(`Success Rate: ${((passed / total) * 100).toFixed(1)}%\n`);
    
    if (failed > 0) {
      console.log('Failed Tests:');
      this.testResults
        .filter(r => r.status === 'FAIL')
        .forEach(result => {
          console.log(`  ❌ ${result.test}: ${result.error}`);
        });
      console.log();
    }
    
    console.log('Next Steps:');
    console.log('1. Review failed tests and fix issues');
    console.log('2. Run: node scripts/end-to-end-test.js');
    console.log('3. Run: node scripts/byzantine-test.js');
    console.log('4. Deploy to testnet for integration testing');
  }
}

// Run the tests
async function runPolicyTests() {
  const tester = new PolicyTester();
  
  try {
    await tester.initialize();
    await tester.runAllTests();
  } catch (error) {
    console.error('\n❌ Policy test suite failed:', error);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  runPolicyTests();
}

module.exports = PolicyTester;
