const { DefaultAzureCredential } = require('@azure/identity');
const { AuthorizationManagementClient } = require('@azure/arm-authorization');
require('dotenv').config();

class AzureIamConnector {
  constructor() {
    // Use DefaultAzureCredential which tries multiple authentication methods
    this.credential = new DefaultAzureCredential();
    
    // Initialize authorization client
    this.authorizationClient = new AuthorizationManagementClient(
      this.credential, 
      process.env.AZURE_SUBSCRIPTION_ID
    );
  }

  /**
   * Get role definitions for a scope
   * @param {string} scope - The scope (e.g., subscription or resource group)
   * @returns {Promise<Array>} - List of role definitions
   */
  async getRoleDefinitions(scope) {
    try {
      const roleDefinitions = [];
      const iterator = this.authorizationClient.roleDefinitions.list(scope);
      
      for await (const definition of iterator) {
        roleDefinitions.push(definition);
      }
      
      return roleDefinitions;
    } catch (error) {
      console.error('Error getting role definitions:', error);
      throw error;
    }
  }

  /**
   * Get role assignments for a scope
   * @param {string} scope - The scope (e.g., subscription or resource group)
   * @returns {Promise<Array>} - List of role assignments
   */
  async getRoleAssignments(scope) {
    try {
      const roleAssignments = [];
      const iterator = this.authorizationClient.roleAssignments.listForScope(scope);
      
      for await (const assignment of iterator) {
        roleAssignments.push(assignment);
      }
      
      return roleAssignments;
    } catch (error) {
      console.error('Error getting role assignments:', error);
      throw error;
    }
  }

  /**
   * Create a role assignment
   * @param {string} scope - The scope for the role assignment
   * @param {string} roleDefinitionId - The role definition ID
   * @param {string} principalId - The principal ID (object ID of user, group, or service principal)
   * @returns {Promise<object>} - Created role assignment
   */
  async createRoleAssignment(scope, roleDefinitionId, principalId) {
    try {
      // Generate a unique name for the role assignment (GUID)
      const roleAssignmentName = this._generateGuid();
      
      const result = await this.authorizationClient.roleAssignments.create(
        scope,
        roleAssignmentName,
        {
          roleDefinitionId,
          principalId
        }
      );
      
      return result;
    } catch (error) {
      console.error('Error creating role assignment:', error);
      throw error;
    }
  }

  /**
   * Delete a role assignment
   * @param {string} scope - The scope of the role assignment
   * @param {string} roleAssignmentId - The ID of the role assignment
   * @returns {Promise<void>}
   */
  async deleteRoleAssignment(scope, roleAssignmentId) {
    try {
      await this.authorizationClient.roleAssignments.deleteMethod(scope, roleAssignmentId);
      console.log(`Role assignment ${roleAssignmentId} deleted`);
    } catch (error) {
      console.error('Error deleting role assignment:', error);
      throw error;
    }
  }
  
  /**
   * Validate an access request against blockchain-based IAM
   * @param {string} resourceId - ID of the Azure resource
   * @param {string} principalId - ID of the principal requesting access
   * @param {object} blockchainProof - Proof from blockchain
   * @returns {Promise<boolean>} - Whether access is granted
   */
  async validateAccess(resourceId, principalId, blockchainProof) {
    try {
      // Verify the blockchain proof is valid
      if (!blockchainProof || !blockchainProof.signature) {
        return false;
      }
      
      // Log the validation attempt for audit
      console.log(`[Azure] Validating access to ${resourceId} for ${principalId}`);
      console.log(`[Azure] Blockchain proof transaction: ${blockchainProof.txHash}`);
      
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
   * Generate a GUID for role assignment
   * @private
   * @returns {string} - A GUID string
   */
  _generateGuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}

module.exports = AzureIamConnector;