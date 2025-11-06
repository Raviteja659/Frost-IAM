#!/usr/bin/env node

/**
 * Test AWS Connection and Credentials
 * Validates AWS SDK configuration and connectivity
 */

const AwsIamConnector = require('../cloud-integration/aws-iam-connector');
require('dotenv').config();

async function testAwsConnection() {
  console.log('🔍 Testing AWS Connection...\n');
  
  // Check environment variables
  console.log('1. Checking environment variables...');
  const requiredEnvVars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'];
  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    console.error('❌ Missing environment variables:', missingVars.join(', '));
    console.log('\nPlease set these variables in your .env file:');
    missingVars.forEach(varName => {
      console.log(`${varName}=your_value_here`);
    });
    process.exit(1);
  }
  console.log('✅ Environment variables configured\n');
  
  // Initialize AWS connector
  console.log('2. Initializing AWS IAM Connector...');
  let awsConnector;
  try {
    awsConnector = new AwsIamConnector(process.env.AWS_REGION || 'us-east-1');
    console.log('✅ AWS IAM Connector initialized\n');
  } catch (error) {
    console.error('❌ Failed to initialize AWS connector:', error.message);
    process.exit(1);
  }
  
  // Test IAM connectivity
  console.log('3. Testing IAM connectivity...');
  try {
    // Try to verify a user (this will fail if user doesn't exist, but proves connectivity)
    const testUsername = 'test-connectivity-user';
    const userExists = await awsConnector.verifyUser(testUsername);
    console.log(`✅ IAM API accessible (test user exists: ${userExists})\n`);
  } catch (error) {
    if (error.name === 'CredentialsProviderError' || error.name === 'InvalidClientTokenId') {
      console.error('❌ Invalid AWS credentials');
      console.error('   Please check your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY\n');
      process.exit(1);
    } else if (error.name === 'AccessDenied') {
      console.log('⚠️  Credentials valid but lack IAM permissions');
      console.log('   This is OK for testing connectivity\n');
    } else {
      console.error('❌ IAM connectivity test failed:', error.message);
      process.exit(1);
    }
  }
  
  // Test STS connectivity
  console.log('4. Testing STS connectivity...');
  try {
    // Try to assume a role (will fail if role doesn't exist, but proves connectivity)
    const testRoleArn = process.env.AWS_TEST_ROLE_ARN || 'arn:aws:iam::123456789012:role/test-role';
    try {
      await awsConnector.assumeRole(testRoleArn, 'test-session', 900);
      console.log('✅ STS API accessible and role assumption successful\n');
    } catch (roleError) {
      if (roleError.name === 'NoSuchEntity' || roleError.message.includes('not authorized')) {
        console.log('✅ STS API accessible (test role not found, but API is reachable)\n');
      } else {
        throw roleError;
      }
    }
  } catch (error) {
    console.error('❌ STS connectivity test failed:', error.message);
    console.log('   This may indicate network issues or insufficient permissions\n');
  }
  
  // Test blockchain proof validation
  console.log('5. Testing blockchain proof validation...');
  const mockProof = {
    resourceId: 'arn:aws:s3:::test-bucket',
    principalId: 'user:test@example.com',
    signature: '0x1234567890abcdef',
    timestamp: Date.now(),
    txHash: '0xabcdef1234567890'
  };
  
  const isValid = await awsConnector.validateAccess(
    'arn:aws:s3:::test-bucket',
    'user:test@example.com',
    mockProof
  );
  
  if (isValid) {
    console.log('✅ Blockchain proof validation working\n');
  } else {
    console.log('⚠️  Blockchain proof validation returned false (expected for mock data)\n');
  }
  
  // Summary
  console.log('═══════════════════════════════════════');
  console.log('✅ AWS Connection Test Complete');
  console.log('═══════════════════════════════════════');
  console.log('\nNext steps:');
  console.log('1. Create a test IAM role for your application');
  console.log('2. Set AWS_TEST_ROLE_ARN in your .env file');
  console.log('3. Run: node scripts/test-frost.js');
}

// Run the test
testAwsConnection().catch(error => {
  console.error('\n❌ Unexpected error:', error);
  process.exit(1);
});