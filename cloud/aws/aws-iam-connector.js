const { IAMClient, GetUserCommand, CreateUserCommand, AttachUserPolicyCommand } = require('@aws-sdk/client-iam');
const { STSClient, AssumeRoleCommand } = require('@aws-sdk/client-sts');
require('dotenv').config();

class AwsIamConnector {
  constructor(region = 'us-east-1') {
    // Initialize IAM client
    this.iamClient = new IAMClient({ 
      region,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    });
    
    // Initialize STS client for temporary credentials
    this.stsClient = new STSClient({ 
      region,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    });
  }

  /**
   * Verify if a user exists in AWS IAM
   * @param {string} username - The IAM username
   * @returns {Promise<boolean>} - True if user exists
   */
  async verifyUser(username) {
    try {
      const command = new GetUserCommand({
        UserName: username
      });
      const response = await this.iamClient.send(command);
      return !!response.User;
    } catch (error) {
      if (error.name === 'NoSuchEntityException') {
        return false;
      }
      throw error;
    }
  }

  /**
   * Create a new user in AWS IAM
   * @param {string} username - The IAM username
   * @returns {Promise<object>} - User creation result
   */
  async createUser(username) {
    try {
      const command = new CreateUserCommand({
        UserName: username
      });
      return await this.iamClient.send(command);
    } catch (error) {
      console.error('Error creating user:', error);
      throw error;
    }
  }

  /**
   * Attach policy to user
   * @param {string} username - The IAM username
   * @param {string} policyArn - The policy ARN to attach
   * @returns {Promise<object>} - Policy attachment result
   */
  async attachPolicy(username, policyArn) {
    try {
      const command = new AttachUserPolicyCommand({
        UserName: username,
        PolicyArn: policyArn
      });
      return await this.iamClient.send(command);
    } catch (error) {
      console.error('Error attaching policy:', error);
      throw error;
    }
  }

  /**
   * Generate temporary credentials using STS
   * @param {string} roleArn - The role ARN to assume
   * @param {string} sessionName - Name for the temporary session
   * @param {number} durationSeconds - Duration of the temporary credentials
   * @returns {Promise<object>} - Temporary credentials
   */
  async assumeRole(roleArn, sessionName, durationSeconds = 3600) {
    try {
      const command = new AssumeRoleCommand({
        RoleArn: roleArn,
        RoleSessionName: sessionName,
        DurationSeconds: durationSeconds
      });
      
      const response = await this.stsClient.send(command);
      return {
        accessKeyId: response.Credentials.AccessKeyId,
        secretAccessKey: response.Credentials.SecretAccessKey,
        sessionToken: response.Credentials.SessionToken,
        expiration: response.Credentials.Expiration
      };
    } catch (error) {
      console.error('Error assuming role:', error);
      throw error;
    }
  }
  
  /**
   * Validate an access request against blockchain-based IAM
   * @param {string} resourceArn - ARN of the resource
   * @param {string} principalId - ID of the principal requesting access
   * @param {object} blockchainProof - Proof from blockchain
   * @returns {Promise<boolean>} - Whether access is granted
   */
  async validateAccess(resourceArn, principalId, blockchainProof) {
    try {
      // Verify the blockchain proof is valid
      if (!blockchainProof || !blockchainProof.signature) {
        return false;
      }
      
      // Extract resource type from ARN
      const resourceType = this._getResourceTypeFromArn(resourceArn);
      
      // Log the validation attempt for audit
      console.log(`[AWS] Validating access to ${resourceType}:${resourceArn} for ${principalId}`);
      console.log(`[AWS] Blockchain proof transaction: ${blockchainProof.txHash}`);
      
      // In a production environment, validate against blockchain state
      // For this implementation, we'll assume the proof is valid if it contains expected fields
      return (
        blockchainProof.resourceId && 
        blockchainProof.principalId === principalId &&
        blockchainProof.timestamp > Date.now() - 300000 // Valid for 5 minutes
      );
    } catch (error) {
      console.error('Error validating access:', error);
      return false;
    }
  }
  
  /**
   * Extract resource type from ARN
   * @private
   * @param {string} arn - The AWS ARN
   * @returns {string} - Resource type
   */
  _getResourceTypeFromArn(arn) {
    const parts = arn.split(':');
    if (parts.length >= 6) {
      const service = parts[2];
      const resourcePath = parts[5];
      const resourceType = resourcePath.split('/')[0];
      return `${service}/${resourceType}`;
    }
    return 'unknown';
  }
}

module.exports = AwsIamConnector;