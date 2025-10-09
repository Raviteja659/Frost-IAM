// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title FrostIAM
 * @dev Implements a decentralized IAM system using FROST threshold signatures
 */
contract FrostIAM is Ownable {
    using EnumerableSet for EnumerableSet.AddressSet;

    // Struct to store policy information
    struct Policy {
        bytes32 policyId;
        address resource;
        bytes4 functionSelector;
        uint256 threshold;
        EnumerableSet.AddressSet approvers;
        mapping(address => bool) approvals;
        bool executed;
    }

    // Mapping from policy ID to Policy
    mapping(bytes32 => Policy) private _policies;
    
    // Counter for policy IDs
    uint256 private _policyCounter;

    // Events
    event PolicyCreated(
        bytes32 indexed policyId,
        address indexed resource,
        bytes4 functionSelector,
        uint256 threshold
    );
    
    event ApprovalReceived(
        bytes32 indexed policyId,
        address approver,
        bytes signature
    );
    
    event PolicyExecuted(
        bytes32 indexed policyId,
        bool success,
        bytes result
    );

    /**
     * @dev Creates a new access control policy
     * @param resource The target contract address
     * @param functionSelector The function selector to control access to
     * @param approvers List of addresses that can approve this policy
     * @param threshold Number of approvals required
     */
    function createPolicy(
        address resource,
        bytes4 functionSelector,
        address[] calldata approvers,
        uint256 threshold
    ) external onlyOwner returns (bytes32) {
        require(approvers.length >= threshold, "FrostIAM: threshold too high");
        require(threshold > 0, "FrostIAM: threshold cannot be zero");
        
        bytes32 policyId = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                _policyCounter++,
                block.timestamp
            )
        );
        
        Policy storage policy = _policies[policyId];
        policy.policyId = policyId;
        policy.resource = resource;
        policy.functionSelector = functionSelector;
        policy.threshold = threshold;
        
        for (uint256 i = 0; i < approvers.length; i++) {
            policy.approvers.add(approvers[i]);
        }
        
        emit PolicyCreated(policyId, resource, functionSelector, threshold);
        
        return policyId;
    }
    
    /**
     * @dev Approves a policy with a FROST signature
     * @param policyId The ID of the policy to approve
     * @param signature The FROST signature
     */
    function approvePolicy(bytes32 policyId, bytes calldata signature) external {
        Policy storage policy = _policies[policyId];
        require(policy.policyId != 0, "FrostIAM: policy does not exist");
        require(!policy.executed, "FrostIAM: policy already executed");
        require(!policy.approvals[msg.sender], "FrostIAM: already approved");
        require(policy.approvers.contains(msg.sender), "FrostIAM: not an approver");
        
        // In a real implementation, verify the FROST signature here
        // For now, we'll just mark the approval
        policy.approvals[msg.sender] = true;
        
        emit ApprovalReceived(policyId, msg.sender, signature);
    }
    
    /**
     * @dev Executes a policy if threshold is met
     * @param policyId The ID of the policy to execute
     * @param data The calldata to send to the target contract
     */
    function executePolicy(bytes32 policyId, bytes calldata data) external {
        Policy storage policy = _policies[policyId];
        require(policy.policyId != 0, "FrostIAM: policy does not exist");
        require(!policy.executed, "FrostIAM: policy already executed");
        
        // Count approvals
        uint256 approvalCount = 0;
        uint256 approversLength = policy.approvers.length();
        
        for (uint256 i = 0; i < approversLength; i++) {
            if (policy.approvals[policy.approvers.at(i)]) {
                approvalCount++;
            }
        }
        
        require(approvalCount >= policy.threshold, "FrostIAM: insufficient approvals");
        
        // Mark as executed to prevent reentrancy
        policy.executed = true;
        
        // Execute the call
        (bool success, bytes memory result) = policy.resource.call(
            abi.encodePacked(policy.functionSelector, data)
        );
        
        emit PolicyExecuted(policyId, success, result);
        
        require(success, "FrostIAM: execution failed");
    }
    
    // View functions
    function getPolicyApprovalCount(bytes32 policyId) external view returns (uint256) {
        Policy storage policy = _policies[policyId];
        require(policy.policyId != 0, "FrostIAM: policy does not exist");
        
        uint256 count = 0;
        uint256 approversLength = policy.approvers.length();
        
        for (uint256 i = 0; i < approversLength; i++) {
            if (policy.approvals[policy.approvers.at(i)]) {
                count++;
            }
        }
        
        return count;
    }
    
    function isPolicyApprovedBy(bytes32 policyId, address approver) external view returns (bool) {
        return _policies[policyId].approvals[approver];
    }
    
    function getPolicyThreshold(bytes32 policyId) external view returns (uint256) {
        return _policies[policyId].threshold;
    }
    
    function isPolicyExecuted(bytes32 policyId) external view returns (bool) {
        return _policies[policyId].executed;
    }
}