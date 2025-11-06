// scripts/deploy.js
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("Deploying contracts to:", network.name);
  
  // Get the signers (accounts)
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying contracts with account: ${deployer.address}`);
  
  // Get initial balance
  const initialBalance = await ethers.provider.getBalance(deployer.address);
  console.log(`Initial balance: ${ethers.utils.formatEther(initialBalance)} ETH`);

  try {
    // Deploy FrostMultiSig contract
    console.log("Deploying FrostMultiSig...");
    const FrostMultiSig = await ethers.getContractFactory("FrostMultiSig");
    const frostMultiSig = await FrostMultiSig.deploy();
    await frostMultiSig.deployed();
    const frostMultiSigAddress = frostMultiSig.address;
    console.log(`FrostMultiSig deployed to: ${frostMultiSigAddress}`);
    
    // Set up initial signers and threshold
    console.log("Initializing FrostMultiSig...");
    const initialSigners = [
      deployer.address, 
      // Add additional test signers here
      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    ];
    const threshold = 2; // 2 out of 3 signers required
    
    // Initialize the MultiSig
    const initTx = await frostMultiSig.initialize(initialSigners, threshold);
    await initTx.wait();
    console.log(`FrostMultiSig initialized with threshold: ${threshold}`);
    
    // Deploy AccessControlRegistry contract
    console.log("Deploying AccessControlRegistry...");
    const AccessControlRegistry = await ethers.getContractFactory("AccessControlRegistry");
    const accessControlRegistry = await AccessControlRegistry.deploy(deployer.address, frostMultiSigAddress);
    await accessControlRegistry.deployed();
    const accessControlRegistryAddress = accessControlRegistry.address;
    console.log(`AccessControlRegistry deployed to: ${accessControlRegistryAddress}`);
    
    // Grant OPERATOR_ROLE to deployer for testing
    const OPERATOR_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("OPERATOR_ROLE"));
    const grantRoleTx = await accessControlRegistry.grantRole(OPERATOR_ROLE, deployer.address);
    await grantRoleTx.wait();
    console.log("Granted OPERATOR_ROLE to deployer");
    
    // Create some example policies for testing
    if (network.name === "localhost" || network.name === "hardhat") {
      console.log("Setting up test policies...");
      
      // Create policy for AWS S3 bucket - USE KECCAK256 HASH INSTEAD OF DIRECT ENCODING
      // const awsS3ResourceId = ethers.encodeBytes32String("arn:aws:s3:::example-bucket"); // REMOVED
      const awsS3ResourceId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("arn:aws:s3:::example-bucket"));
      const awsCloudProvider = 1; // AWS
      const noExpiry = 0; // No expiry
      const requiresFrostSig = true;
      
      const tx1 = await accessControlRegistry.createResourcePolicy(
        awsS3ResourceId,
        awsCloudProvider,
        noExpiry,
        requiresFrostSig
      );
      await tx1.wait();
      console.log("Created policy for AWS S3 bucket");
      
      // Create policy for Azure Storage - USE KECCAK256 HASH INSTEAD OF DIRECT ENCODING
      // const azureStorageResourceId = ethers.encodeBytes32String("azure:/subscriptions/example/resourceGroups/storage"); // REMOVED
      const azureStorageResourceId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("azure:/subscriptions/example/resourceGroups/storage"));
      const azureCloudProvider = 2; // Azure
      
      const tx2 = await accessControlRegistry.createResourcePolicy(
        azureStorageResourceId,
        azureCloudProvider,
        noExpiry,
        requiresFrostSig
      );
      await tx2.wait();
      console.log("Created policy for Azure Storage");
      
      // Grant permissions to a principal
      // const principalId = ethers.encodeBytes32String("user:alice@example.com"); // REMOVED
      const principalId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("user:alice@example.com"));
      
      const tx3 = await accessControlRegistry.grantPermission(awsS3ResourceId, principalId);
      await tx3.wait();
      console.log("Granted permission for AWS S3 to Alice");
      
      const tx4 = await accessControlRegistry.grantPermission(azureStorageResourceId, principalId);
      await tx4.wait();
      console.log("Granted permission for Azure Storage to Alice");
    }
    
    // Get final balance and calculate gas used
    const finalBalance = await ethers.provider.getBalance(deployer.address);
    const ethUsed = ethers.utils.formatEther(initialBalance.sub(finalBalance));
    console.log(`Deployment complete! Used ${ethUsed} ETH for gas`);
    
    // Save deployment addresses to file
    const deploymentData = {
      network: network.name,
      frostMultiSig: frostMultiSigAddress,
      accessControlRegistry: accessControlRegistryAddress,
      deployer: deployer.address,
      deployedAt: new Date().toISOString()
    };
    
    const deploymentDir = path.join(__dirname, '../deployments');
    if (!fs.existsSync(deploymentDir)) {
      fs.mkdirSync(deploymentDir);
    }
    
    fs.writeFileSync(
      path.join(deploymentDir, `${network.name}.json`),
      JSON.stringify(deploymentData, null, 2)
    );
    
    // Create or update .env file with contract addresses
    const envPath = path.join(__dirname, '../.env');
    let envContent = '';
    
    if (fs.existsSync(envPath)) {
      envContent = fs.readFileSync(envPath, 'utf8');
    }
    
    // Update contract addresses in .env
    if (!envContent.includes('FROST_MULTISIG_ADDRESS=')) {
      envContent += `\nFROST_MULTISIG_ADDRESS=${frostMultiSigAddress}`;
    } else {
      envContent = envContent.replace(
        /FROST_MULTISIG_ADDRESS=.*/,
        `FROST_MULTISIG_ADDRESS=${frostMultiSigAddress}`
      );
    }
    
    if (!envContent.includes('ACCESS_CONTROL_REGISTRY_ADDRESS=')) {
      envContent += `\nACCESS_CONTROL_REGISTRY_ADDRESS=${accessControlRegistryAddress}`;
    } else {
      envContent = envContent.replace(
        /ACCESS_CONTROL_REGISTRY_ADDRESS=.*/,
        `ACCESS_CONTROL_REGISTRY_ADDRESS=${accessControlRegistryAddress}`
      );
    }
    
    fs.writeFileSync(envPath, envContent);
    console.log(`Deployment addresses saved to ${path.join(deploymentDir, `${network.name}.json`)}`);
    console.log('.env file updated with contract addresses');
    
  } catch (error) {
    console.error("Deployment failed:", error);
    process.exitCode = 1;
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });