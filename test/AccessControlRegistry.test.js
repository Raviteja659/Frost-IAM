// test/AccessControlRegistry.test.js
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

describe("AccessControlRegistry Contract", function () {
  // Fixture that deploys the FrostMultiSig and AccessControlRegistry contracts
  async function deployFixture() {
    // Get signers
    const [admin, operator, user1, user2] = await ethers.getSigners();
    
    // Deploy FrostMultiSig
    const FrostMultiSig = await ethers.getContractFactory("FrostMultiSig");
    const frostMultiSig = await FrostMultiSig.deploy();
    
    // Initialize with signers and threshold
    const signers = [admin.address, operator.address];
    const threshold = 1; // 1-of-2 threshold for simplicity in testing
    
    await frostMultiSig.initialize(signers, threshold);
    
    // Deploy AccessControlRegistry
    const AccessControlRegistry = await ethers.getContractFactory("AccessControlRegistry");
    const accessControlRegistry = await AccessControlRegistry.deploy(admin.address, frostMultiSig.address);
    
    // Role constants
    const ADMIN_ROLE = await accessControlRegistry.ADMIN_ROLE();
    const OPERATOR_ROLE = await accessControlRegistry.OPERATOR_ROLE();
    
    // Grant operator role to the operator
    await accessControlRegistry.connect(admin).grantRole(OPERATOR_ROLE, operator.address);
    
    return { 
      accessControlRegistry, 
      frostMultiSig, 
      admin, 
      operator, 
      user1, 
      user2,
      ADMIN_ROLE,
      OPERATOR_ROLE
    };
  }

  describe("Initialization", function () {
    it("Should set the admin role correctly", async function () {
      const { accessControlRegistry, admin, ADMIN_ROLE } = await loadFixture(deployFixture);
      
      expect(await accessControlRegistry.hasRole(ADMIN_ROLE, admin.address)).to.be.true;
    });

    it("Should set the FrostMultiSig address correctly", async function () {
      const { accessControlRegistry, frostMultiSig } = await loadFixture(deployFixture);
      
      expect(await accessControlRegistry.frostMultiSig()).to.equal(frostMultiSig.address);
    });
  });

  describe("Role Management", function () {
    it("Admin should be able to grant roles", async function () {
      const { accessControlRegistry, admin, user1, OPERATOR_ROLE } = await loadFixture(deployFixture);
      
      await accessControlRegistry.connect(admin).grantRole(OPERATOR_ROLE, user1.address);
      
      expect(await accessControlRegistry.hasRole(OPERATOR_ROLE, user1.address)).to.be.true;
    });

    it("Non-admin should not be able to grant roles", async function () {
      const { accessControlRegistry, user1, user2, OPERATOR_ROLE } = await loadFixture(deployFixture);
      
      await expect(
        accessControlRegistry.connect(user1).grantRole(OPERATOR_ROLE, user2.address)
      ).to.be.reverted;
    });
  });

  describe("Policy Management", function () {
    it("Admin should be able to create a resource policy", async function () {
      const { accessControlRegistry, admin } = await loadFixture(deployFixture);
      
      const resourceId = ethers.utils.formatBytes32String("arn:aws:s3:::example-bucket");
      const cloudProvider = 1; // AWS
      const expiryTime = 0; // No expiry
      const requiresFrostSig = true;
      
      await accessControlRegistry.connect(admin).createResourcePolicy(
        resourceId,
        cloudProvider,
        expiryTime,
        requiresFrostSig
      );
      
      const policy = await accessControlRegistry.resourcePolicies(resourceId);
      
      expect(policy.cloudProvider).to.equal(cloudProvider);
      expect(policy.requiresFrostSig).to.equal(requiresFrostSig);
      expect(policy.created).to.be.gt(0);
    });

    it("Should not allow creating a policy for an existing resource", async function () {
      const { accessControlRegistry, admin } = await loadFixture(deployFixture);
      
      const resourceId = ethers.utils.formatBytes32String("arn:aws:s3:::example-bucket");
      const cloudProvider = 1; // AWS
      const expiryTime = 0; // No expiry
      const requiresFrostSig = true;
      
      // Create the policy once
      await accessControlRegistry.connect(admin).createResourcePolicy(
        resourceId,
        cloudProvider,
        expiryTime,
        requiresFrostSig
      );
      
      // Attempt to create it again
      await expect(
        accessControlRegistry.connect(admin).createResourcePolicy(
          resourceId,
          cloudProvider,
          expiryTime,
          requiresFrostSig
        )
      ).to.be.revertedWith("Policy already exists");
    });

    it("Non-admin should not be able to create resource policies", async function () {
      const { accessControlRegistry, operator } = await loadFixture(deployFixture);
      
      const resourceId = ethers.utils.formatBytes32String("arn:aws:s3:::example-bucket");
      const cloudProvider = 1; // AWS
      const expiryTime = 0; // No expiry
      const requiresFrostSig = true;
      
      await expect(
        accessControlRegistry.connect(operator).createResourcePolicy(
          resourceId,
          cloudProvider,
          expiryTime,
          requiresFrostSig
        )
      ).to.be.reverted;
    });
  });

  describe("Permission Management", function () {
    it("Operator should be able to grant and revoke permissions", async function () {
      const { accessControlRegistry, admin, operator } = await loadFixture(deployFixture);
      
      const resourceId = ethers.utils.formatBytes32String("arn:aws:s3:::example-bucket");
      const principalId = ethers.utils.formatBytes32String("user:alice@example.com");
      const cloudProvider = 1; // AWS
      const expiryTime = 0; // No expiry
      const requiresFrostSig = true;
      
      // Create policy
      await accessControlRegistry.connect(admin).createResourcePolicy(
        resourceId,
        cloudProvider,
        expiryTime,
        requiresFrostSig
      );
      
      // Initially no permission
      expect(await accessControlRegistry.hasPermission(resourceId, principalId)).to.be.false;
      
      // Grant permission
      await accessControlRegistry.connect(operator).grantPermission(resourceId, principalId);
      
      // Now should have permission
      expect(await accessControlRegistry.hasPermission(resourceId, principalId)).to.be.true;
      
      // Revoke permission
      await accessControlRegistry.connect(operator).revokePermission(resourceId, principalId);
      
      // Now should not have permission
      expect(await accessControlRegistry.hasPermission(resourceId, principalId)).to.be.false;
    });

    it("Should not allow granting permissions for non-existent policies", async function () {
      const { accessControlRegistry, operator } = await loadFixture(deployFixture);
      
      const resourceId = ethers.utils.formatBytes32String("non-existent-resource");
      const principalId = ethers.utils.formatBytes32String("user:alice@example.com");
      
      await expect(
        accessControlRegistry.connect(operator).grantPermission(resourceId, principalId)
      ).to.be.revertedWith("Policy doesn't exist");
    });

    it("Should not allow granting permissions for expired policies", async function () {
      const { accessControlRegistry, admin, operator } = await loadFixture(deployFixture);
      
      const resourceId = ethers.utils.formatBytes32String("arn:aws:s3:::example-bucket");
      const principalId = ethers.utils.formatBytes32String("user:alice@example.com");
      const cloudProvider = 1; // AWS
      
      // Current timestamp
      const blockNum = await ethers.provider.getBlockNumber();
      const block = await ethers.provider.getBlock(blockNum);
      const currentTime = block.timestamp;
      
      // Set expiry time in the past
      const expiryTime = currentTime - 3600; // 1 hour ago
      const requiresFrostSig = true;
      
      // Create policy with past expiry
      await accessControlRegistry.connect(admin).createResourcePolicy(
        resourceId,
        cloudProvider,
        expiryTime,
        requiresFrostSig
      );
      
      await expect(
        accessControlRegistry.connect(operator).grantPermission(resourceId, principalId)
      ).to.be.revertedWith("Policy expired");
    });

    it("Should check permissions correctly with expiry", async function () {
      const { accessControlRegistry, admin, operator } = await loadFixture(deployFixture);
      
      const resourceId = ethers.utils.formatBytes32String("arn:aws:s3:::example-bucket");
      const principalId = ethers.utils.formatBytes32String("user:alice@example.com");
      const cloudProvider = 1; // AWS
      
      // Current timestamp
      const blockNum = await ethers.provider.getBlockNumber();
      const block = await ethers.provider.getBlock(blockNum);
      const currentTime = block.timestamp;
      
      // Set expiry time in the near future
      const expiryTime = currentTime + 3600; // 1 hour in the future
      const requiresFrostSig = true;
      
      // Create policy
      await accessControlRegistry.connect(admin).createResourcePolicy(
        resourceId,
        cloudProvider,
        expiryTime,
        requiresFrostSig
      );
      
      // Grant permission
      await accessControlRegistry.connect(operator).grantPermission(resourceId, principalId);
      
      // Should have permission now
      expect(await accessControlRegistry.hasPermission(resourceId, principalId)).to.be.true;
      
      // Advance time past expiry
      await ethers.provider.send("evm_increaseTime", [3601]); // 1 hour + 1 second
      await ethers.provider.send("evm_mine");
      
      // Should no longer have permission due to expiry
      expect(await accessControlRegistry.hasPermission(resourceId, principalId)).to.be.false;
    });
  });

  describe("Pausability", function () {
    it("Admin should be able to pause and unpause the contract", async function () {
      const { accessControlRegistry, admin } = await loadFixture(deployFixture);
      
      // Pause
      await accessControlRegistry.connect(admin).pause();
      
      // Check if paused
      expect(await accessControlRegistry.paused()).to.be.true;
      
      // Unpause
      await accessControlRegistry.connect(admin).unpause();
      
      // Check if unpaused
      expect(await accessControlRegistry.paused()).to.be.false;
    });

    it("Should not allow granting permissions when paused", async function () {
      const { accessControlRegistry, admin, operator } = await loadFixture(deployFixture);
      
      const resourceId = ethers.utils.formatBytes32String("arn:aws:s3:::example-bucket");
      const principalId = ethers.utils.formatBytes32String("user:alice@example.com");
      const cloudProvider = 1; // AWS
      const expiryTime = 0; // No expiry
      const requiresFrostSig = true;
      
      // Create policy
      await accessControlRegistry.connect(admin).createResourcePolicy(
        resourceId,
        cloudProvider,
        expiryTime,
        requiresFrostSig
      );
      
      // Pause the contract
      await accessControlRegistry.connect(admin).pause();
      
      // Attempt to grant permission while paused
      await expect(
        accessControlRegistry.connect(operator).grantPermission(resourceId, principalId)
      ).to.be.revertedWith("Pausable: paused");
      
      // Unpause
      await accessControlRegistry.connect(admin).unpause();
      
      // Now should be able to grant permission
      await accessControlRegistry.connect(operator).grantPermission(resourceId, principalId);
      
      expect(await accessControlRegistry.hasPermission(resourceId, principalId)).to.be.true;
    });
  });
});