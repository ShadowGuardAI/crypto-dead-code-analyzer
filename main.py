import argparse
import logging
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_contract(contract_code):
    """
    Analyzes smart contract code for potential dead code related to crypto operations.
    This is a simplified example and would need significant expansion for real-world use.

    Args:
        contract_code (str): The smart contract code to analyze.

    Returns:
        list: A list of warnings or findings related to potential dead code.
    """

    findings = []

    # Example 1: Check for unused cryptographic functions
    if "hashlib.sha256" in contract_code and contract_code.count("hashlib.sha256") <= 1: # example usage condition
        findings.append("Warning: 'hashlib.sha256' is used infrequently, potentially redundant.")

    # Example 2: Check for unused key generation functions.  This is very basic.
    if "rsa.generate_private_key" in contract_code and contract_code.count("rsa.generate_private_key") <=1:
         findings.append("Warning: 'rsa.generate_private_key' function not consistently used, potential optimization opportunity.")

    # Example 3: Check for functions that are defined but never called.
    # This requires more sophisticated parsing and symbol table analysis.
    # Placeholder - would need a proper parser and static analysis.

    return findings



def simulate_vulnerability(contract_code):
    """
    Simulates a potential vulnerability related to crypto operations.
    This is a deliberately simplified example for demonstration purposes only.

    Args:
        contract_code (str): The smart contract code to simulate against.

    Returns:
        bool: True if a vulnerability is detected (simulated), False otherwise.
    """
    try:
        #Insecure comparison example:
        if "==" in contract_code and "hashlib.sha256" in contract_code:
            logging.warning("Potential Vulnerability: Insecure comparison used with hash. Check for timing attacks and collision risks.")
            return True

        # Insecure random number generation
        if "random.random" in contract_code:
            logging.warning("Potential Vulnerability: Insecure random number generation used. Consider using os.urandom or secrets module.")
            return True


        return False

    except Exception as e:
        logging.error(f"Error during vulnerability simulation: {e}")
        return False


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyze smart contracts for crypto-related dead code and vulnerabilities.")
    parser.add_argument("contract_file", help="Path to the smart contract file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-s", "--simulate", action="store_true", help="Simulate potential vulnerabilities.")
    return parser


def main():
    """
    Main function to drive the crypto dead code analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info(f"Analyzing contract: {args.contract_file}")

    try:
        with open(args.contract_file, "r") as f:
            contract_code = f.read()

        # Perform dead code analysis
        findings = analyze_contract(contract_code)
        if findings:
            logging.warning("Potential dead code findings:")
            for finding in findings:
                logging.warning(f"  - {finding}")
        else:
            logging.info("No potential dead code found.")


        # Optionally simulate vulnerabilities
        if args.simulate:
            if simulate_vulnerability(contract_code):
                logging.warning("Vulnerability simulation triggered. Review code for weaknesses.")
            else:
                logging.info("Vulnerability simulation did not detect any issues (this does not guarantee security!).")


    except FileNotFoundError:
        logging.error(f"Error: Contract file not found: {args.contract_file}")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)

    logging.info("Analysis complete.")


if __name__ == "__main__":
    # Example usage:
    # python main.py my_contract.sol
    # python main.py my_contract.sol -v
    # python main.py my_contract.sol -s
    # python main.py my_contract.sol -v -s

    #Example Contract file.  Needs to exist for the tool to be useful.
    example_contract = """
    pragma solidity ^0.8.0;

    import "hardhat/console.sol";
    import "hardhat/console.sol"; // redundant import, possible dead code.

    import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    import "@openzeppelin/contracts/access/Ownable.sol";


    contract MyToken is ERC20, Ownable {
        using SafeMath for uint256;

        mapping(address => bool) public isBlacklisted;
        uint256 public totalSupplyLimit = 1000000 * (10 ** decimals()); // 1 million tokens limit
        string private _name;
        string private _symbol;


        event TokenCreated(address creator, string name, string symbol);
        event Blacklisted(address account);
        event RemovedFromBlacklist(address account);

        constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {
            _name = name_;
            _symbol = symbol_;
            _mint(msg.sender, 1000 * (10 ** decimals())); // Mint initial supply to the deployer
            emit TokenCreated(msg.sender, name_, symbol_);
        }

        // Custom Minting Function with supply limit
        function mint(address to, uint256 amount) public onlyOwner {
            require(totalSupply() + amount <= totalSupplyLimit, "Mint amount exceeds total supply limit.");
            _mint(to, amount);
        }

        // Blacklisting mechanism (simplified, can be improved)
        function blacklist(address account) public onlyOwner {
            isBlacklisted[account] = true;
            emit Blacklisted(account);
        }

        // Remove address from the blacklist
        function removeFromBlacklist(address account) public onlyOwner {
            isBlacklisted[account] = false;
            emit RemovedFromBlacklist(account);
        }

        // Override transfer functions to check if sender or recipient is blacklisted
        function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override {
            require(!isBlacklisted[from] && !isBlacklisted[to], "Account is blacklisted");
            super._beforeTokenTransfer(from, to, amount);
        }


        function test_hash(bytes memory input) public pure returns (bytes32) {
          bytes32 hashed = keccak256(input); //Example Crypto Operation
          console.log(hashed);
          return hashed;
        }


        function get_name() public view returns(string memory){
          return _name;
        }

        function useless_function(uint256 x, uint256 y) public pure returns (uint256) {
           uint256 z = x + y;
           z = x * z;
           return z;

        }
    }

    library SafeMath {
        function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
            unchecked {
                uint256 sum = a + b;
                if (sum < a) {
                    return (false, 0);
                }
                return (true, sum);
            }
        }

        function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
            unchecked {
                if (b > a) {
                    return (false, 0);
                }
                return (true, a - b);
            }
        }

        function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
            unchecked {
                if (a == 0) {
                    return (true, 0);
                }
                uint256 c = a * b;
                if (c / a != b) {
                    return (false, 0);
                }
                return (true, c);
            }
        }

        function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
            unchecked {
                if (b == 0) {
                    return (false, 0);
                }
                return (true, a / b);
            }
        }

        function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
            unchecked {
                if (b == 0) {
                    return (false, 0);
                }
                return (true, a % b);
            }
        }


        function add(uint256 a, uint256 b) internal pure returns (uint256) {
            return a + b;
        }

        function sub(uint256 a, uint256 b) internal pure returns (uint256) {
            return a - b;
        }

        function mul(uint256 a, uint256 b) internal pure returns (uint256) {
            return a * b;
        }

        function div(uint256 a, uint256 b) internal pure returns (uint256) {
            return a / b;
        }

        function mod(uint256 a, uint256 b) internal pure returns (uint256) {
            return a % b;
        }

        function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
            unchecked {
                require(b <= a, errorMessage);
                return a - b;
            }
        }

        function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
            unchecked {
                require(b > 0, errorMessage);
                return a / b;
            }
        }

        function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
            unchecked {
                require(b > 0, errorMessage);
                return a % b;
            }
        }
    }
    """
    if not os.path.exists("my_contract.sol"):
        with open("my_contract.sol", "w") as f:
            f.write(example_contract)

    main()