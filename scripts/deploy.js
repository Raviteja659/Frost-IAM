const hre = require("hardhat");

async function main() {
  console.log("Deploying FrostIAM contract...");
  
  // Deploy the contract
  const FrostIAM = await hre.ethers.getContractFactory("FrostIAM");
  const frostIAM = await FrostIAM.deploy();
  
  // Wait for deployment to complete
  await frostIAM.waitForDeployment();
  
  console.log(`FrostIAM deployed to: ${await frostIAM.getAddress()}`);
}

// Execute the deployment
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

// used to deploy frost IAM contract //