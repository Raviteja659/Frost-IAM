// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "./FrostMultiSig.sol";

contract AccessControlRegistry is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    // Maps cloud resource to its access control policy
    mapping(bytes32 => Policy) public resourcePolicies;
    
    // Maps principal ID to its permissions
    mapping(bytes32 => mapping(bytes32 => bool)) public permissions;
    
    // Policy structure (packed for gas optimization)
    struct Policy {
        uint32 created;           // Timestamp when created
        uint32 updated;           // Timestamp when last updated
        uint32 expiryTime;        // Expiry timestamp (0 = never)
        uint8 cloudProvider;      // 1=AWS, 2=Azure, 3=GCP, etc.
        bool requiresFrostSig;    // Requires FROST signature for changes
    }
    
    // Events
    event PolicyCreated(bytes32 indexed resourceId, uint8 cloudProvider);
    event PolicyUpdated(bytes32 indexed resourceId, address updatedBy);
    event PermissionGranted(bytes32 indexed resourceId, bytes32 indexed principalId, address grantedBy);
    event PermissionRevoked(bytes32 indexed resourceId, bytes32 indexed principalId, address revokedBy);
    
    FrostMultiSig public frostMultiSig;
    
    constructor(address adminAddress, address frostMultiSigAddress) {
        _grantRole(DEFAULT_ADMIN_ROLE, adminAddress);
        _grantRole(ADMIN_ROLE, adminAddress);
        frostMultiSig = FrostMultiSig(frostMultiSigAddress);
    }
    
    // Create a new resource policy
    function createResourcePolicy(
        bytes32 resourceId,
        uint8 cloudProvider,
        uint32 expiryTime,
        bool requiresFrostSig
    ) external onlyRole(ADMIN_ROLE) {
        require(resourcePolicies[resourceId].created == 0, "Policy already exists");
        
        resourcePolicies[resourceId] = Policy({
            created: uint32(block.timestamp),
            updated: uint32(block.timestamp),
            expiryTime: expiryTime,
            cloudProvider: cloudProvider,
            requiresFrostSig: requiresFrostSig
        });
        
        emit PolicyCreated(resourceId, cloudProvider);
    }
    
    // Grant permission to a principal
    function grantPermission(
        bytes32 resourceId,
        bytes32 principalId
    ) external onlyRole(OPERATOR_ROLE) whenNotPaused {
        require(resourcePolicies[resourceId].created > 0, "Policy doesn't exist");
        
        if (resourcePolicies[resourceId].expiryTime > 0) {
            require(
                block.timestamp < resourcePolicies[resourceId].expiryTime,
                "Policy expired"
            );
        }
        
        permissions[resourceId][principalId] = true;
        resourcePolicies[resourceId].updated = uint32(block.timestamp);
        
        emit PermissionGranted(resourceId, principalId, msg.sender);
    }
    
    // Revoke permission from a principal
    function revokePermission(
        bytes32 resourceId,
        bytes32 principalId
    ) external onlyRole(OPERATOR_ROLE) {
        require(resourcePolicies[resourceId].created > 0, "Policy doesn't exist");
        
        permissions[resourceId][principalId] = false;
        resourcePolicies[resourceId].updated = uint32(block.timestamp);
        
        emit PermissionRevoked(resourceId, principalId, msg.sender);
    }
    
    // Check if a principal has permission to a resource
    function hasPermission(
        bytes32 resourceId,
        bytes32 principalId
    ) external view returns (bool) {
        if (resourcePolicies[resourceId].created == 0) {
            return false;
        }
        
        if (resourcePolicies[resourceId].expiryTime > 0 &&
            block.timestamp >= resourcePolicies[resourceId].expiryTime) {
            return false;
        }
        
        return permissions[resourceId][principalId];
    }
    
    // Admin can pause all permission changes
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }
    
    // Admin can unpause
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}