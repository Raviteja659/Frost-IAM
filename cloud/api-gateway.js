const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { ethers } = require('ethers');
const FrostSignature = require('../scripts/frost-crypto');
const AwsIamConnector = require('./aws-iam-connector');
const AzureIamConnector = require('./azure-iam-connector');

// Load environment variables
require('dotenv').config();

// Create instances of cloud connectors and FROST crypto
const awsConnector = new AwsIamConnector();
const azureConnector = new AzureIamConnector();
const frostCrypto = new FrostSignature();

// Initialize the Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Setup blockchain provider
const provider = new ethers.JsonRpcProvider(process.env.RPC_ENDPOINT || 'http://localhost:8545');

// Load contract ABIs
const frostMultiSigAbi = require('../artifacts/contracts/FrostMultiSig.sol/FrostMultiSig.json').abi;
const accessControlRegistryAbi = require('../artifacts/contracts/AccessControlRegistry.sol/AccessControlRegistry.json').abi;

// Initialize contracts
let frostMultiSigContract;
let accessControlRegistryContract;

// Function to initialize contracts with deployed addresses
const initializeContracts = () => {
  try {
    if (process.env.FROST_MULTISIG_ADDRESS && process.env.ACCESS_CONTROL_REGISTRY_ADDRESS) {
      frostMultiSigContract = new ethers.Contract(
        process.env.FROST_MULTISIG_ADDRESS,
        frostMultiSigAbi,
        provider
      );
      
      accessControlRegistryContract = new ethers.Contract(
        process.env.ACCESS_CONTROL_REGISTRY_ADDRESS,
        accessControlRegistryAbi,
        provider
      );
      
      console.log('Smart contracts initialized successfully');
    } else {
      console.warn('Contract addresses not set in environment variables');
    }
  } catch (error) {
    console.error('Error initializing contracts:', error);
  }
};

// Initialize contracts on startup
initializeContracts();

// API Routes

// Health check endpoint
app.get('/health', (req, res) => {
  const isHealthy = !!(frostMultiSigContract && accessControlRegistryContract);
  res.status(isHealthy ? 200 : 503).json({
    status: isHealthy ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    contracts: {
      frostMultiSig: !!frostMultiSigContract,
      accessControlRegistry: !!accessControlRegistryContract
    }
  });
});

// Get policy information from blockchain
app.get('/policies/:resourceId', async (req, res) => {
  try {
    const resourceId = req.params.resourceId;
    
    if (!accessControlRegistryContract) {
      return res.status(503).json({ error: 'Contract not initialized' });
    }
    
    // Convert resource ID to bytes32
    const resourceIdBytes32 = ethers.encodeBytes32String(resourceId);
    
    // Query policy from blockchain
    const policy = await accessControlRegistryContract.resourcePolicies(resourceIdBytes32);
    
    res.json({
      resourceId,
      policy: {
        created: new Date(policy.created * 1000).toISOString(),
        updated: new Date(policy.updated * 1000).toISOString(),
        expiryTime: policy.expiryTime > 0 ? new Date(policy.expiryTime * 1000).toISOString() : null,
        cloudProvider: ['', 'AWS', 'Azure', 'GCP'][policy.cloudProvider] || 'Unknown',
        requiresFrostSig: policy.requiresFrostSig
      }
    });
  } catch (error) {
    console.error('Error fetching policy:', error);
    res.status(500).json({ error: 'Failed to fetch policy', details: error.message });
  }
});

// Request access to a resource
app.post('/access/request', async (req, res) => {
  try {
    const { resourceId, principalId, cloudProvider, action, signature, publicKeys } = req.body;
    
    if (!resourceId || !principalId || !action || !signature || !publicKeys) {
      return res.status(400).json({ error: 'Missing required parameters' });
    }
    
    if (!accessControlRegistryContract) {
      return res.status(503).json({ error: 'Contract not initialized' });
    }
    
    // Convert IDs to bytes32
    const resourceIdBytes32 = ethers.encodeBytes32String(resourceId);
    const principalIdBytes32 = ethers.encodeBytes32String(principalId);
    
    // Check if principal has permission in blockchain registry
    const hasPermission = await accessControlRegistryContract.hasPermission(resourceIdBytes32, principalIdBytes32);
    
    if (!hasPermission) {
      return res.status(403).json({ error: 'Permission denied on blockchain' });
    }
    
    // Verify FROST signature (in real implementation, this would be more robust)
    // For demo purposes, we'll just check if the signature has the correct format
    if (!signature || typeof signature !== 'string' || signature.length < 10) {
      return res.status(400).json({ error: 'Invalid signature format' });
    }
    
    // Create blockchain proof object
    const blockchainProof = {
      resourceId,
      principalId,
      action,
      signature,
      timestamp: Date.now(),
      txHash: ethers.keccak256(ethers.toUtf8Bytes(`${resourceId}:${principalId}:${action}:${Date.now()}`))
    };
    
    // Validate access on the appropriate cloud provider
    let accessGranted = false;
    let credentials = null;
    
    if (cloudProvider.toUpperCase() === 'AWS') {
      accessGranted = await awsConnector.validateAccess(
        resourceId,
        principalId,
        blockchainProof
      );
      
      if (accessGranted) {
        // Generate temporary AWS credentials for the allowed resource
        // This is a simplified implementation
        credentials = {
          accessKeyId: 'temporary-access-key-id',
          secretAccessKey: 'temporary-secret-access-key',
          sessionToken: 'temporary-session-token',
          expiresAt: new Date(Date.now() + 3600 * 1000).toISOString()
        };
      }
    } else if (cloudProvider.toUpperCase() === 'AZURE') {
      accessGranted = await azureConnector.validateAccess(
        resourceId,
        principalId,
        blockchainProof
      );
      
      if (accessGranted) {
        // Generate temporary Azure access token
        // This is a simplified implementation
        credentials = {
          accessToken: 'temporary-azure-access-token',
          expiresAt: new Date(Date.now() + 3600 * 1000).toISOString()
        };
      }
    } else {
      return res.status(400).json({ error: 'Unsupported cloud provider' });
    }
    
    if (accessGranted) {
      res.json({
        status: 'access_granted',
        provider: cloudProvider,
        resourceId,
        principalId,
        credentials,
        proof: {
          txHash: blockchainProof.txHash,
          timestamp: new Date(blockchainProof.timestamp).toISOString()
        }
      });
    } else {
      res.status(403).json({ error: 'Access validation failed' });
    }
  } catch (error) {
    console.error('Error processing access request:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Create FROST key shares for a group
app.post('/frost/generate-shares', (req, res) => {
  try {
    const { participants, threshold } = req.body;
    
    if (!participants || !threshold) {
      return res.status(400).json({ error: 'Missing required parameters' });
    }
    
    if (participants < 1 || threshold < 1 || threshold > participants) {
      return res.status(400).json({ 
        error: 'Invalid parameters', 
        details: 'Threshold must be between 1 and the number of participants' 
      });
    }
    
    // Generate key shares
    const keyShares = frostCrypto.generateKeyShares(participants, threshold);
    
    // Return only the necessary information (keep private shares secure)
    res.json({
      groupPublicKey: keyShares.groupPublicKey,
      publicShares: keyShares.publicShares,
      threshold: keyShares.threshold,
      total: keyShares.total,
      // In a real application, private shares should be distributed securely to participants
      // For demo purposes, we're returning them here
      shares: keyShares.shares.map(share => ({ 
        index: share.index,
        // In production, don't expose the actual value in the response
        value: `share_${share.index}_secure_value` 
      }))
    });
  } catch (error) {
    console.error('Error generating FROST shares:', error);
    res.status(500).json({ error: 'Failed to generate shares', details: error.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;