# Decentralized Cloud Resource Access Control

A decentralized cloud resource access control system using FROST threshold signatures and gas-optimized smart contracts.

## Project Structure

```
frost-iam/
├── contracts/                    # Smart contracts
│   └── access-control/           # Access control related contracts
│       └── FrostIAM.sol          # Main IAM contract
├── scripts/                      # Deployment and utility scripts
│   └── deploy.js                 # Deployment script
├── test/                         # Test files
├── hardhat.config.js             # Hardhat configuration
└── README.md                     # Project documentation
```

## Prerequisites

- Node.js (v20 or later recommended)
- npm (v9 or later) or yarn
- Hardhat

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd frost-iam
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## Testing

To run the test suite:

```bash
npx hardhat test
```

## Deployment

### Local Development

1. Start a local Hardhat node:
   ```bash
   npx hardhat node
   ```

2. In a separate terminal, deploy the contracts:
   ```bash
   npx hardhat run scripts/deploy.js --network localhost
   ```

### Testnet/Mainnet

1. Create a `.env` file with your private keys and API keys:
   ```
   PRIVATE_KEY=your_private_key
   INFURA_API_KEY=your_infura_api_key
   ETHERSCAN_API_KEY=your_etherscan_api_key
   ```

2. Deploy to a specific network (e.g., sepolia):
   ```bash
   npx hardhat run scripts/deploy.js --network sepolia
   ```

## Smart Contract Overview

### FrostIAM.sol

The main contract that implements decentralized access control using FROST threshold signatures.

Key features:
- Policy-based access control
- Threshold signature verification
- Multi-signature approval workflow
- Gas-optimized storage

## License

MIT

## Author

Ravi Teja Gandu  
National College of Ireland  
MSc in Cloud Computing
