import os
import time
import json
import random
import logging
from typing import List, Dict, Any, Optional

import requests
from web3 import Web3
from web3.exceptions import ConnectionError, BadFunctionCallOutput
from web3.contract import Contract
from web3.datastructures import AttributeDict

# --- Configuration & Constants ---

# Configure logging for clear output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Mock environment variables - in a real application, these would be in a .env file
# and loaded using a library like python-dotenv.
SOURCE_CHAIN_RPC_URL = "https://mock.source.chain.rpc/"
DESTINATION_CHAIN_RPC_URL = "https://mock.destination.chain.rpc/"
SOURCE_BRIDGE_CONTRACT_ADDRESS = Web3.to_checksum_address("0x1234567890123456789012345678901234567890")
DESTINATION_TOKEN_CONTRACT_ADDRESS = Web3.to_checksum_address("0x0987654321098765432109876543210987654321")
RELAYER_PRIVATE_KEY = "0x" + "f" * 64 # A dummy private key for simulation purposes

# A mock block explorer API for transaction confirmation simulation
MOCK_EXPLORER_API_URL = "https://api.mock-source-scan.io/api"

# Contract ABIs (Application Binary Interfaces) - simplified for this simulation
SOURCE_BRIDGE_ABI = json.dumps([
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "sender", "type": "address"},
            {"indexed": True, "name": "recipient", "type": "address"},
            {"indexed": False, "name": "amount", "type": "uint256"},
            {"indexed": False, "name": "nonce", "type": "uint64"},
            {"indexed": True, "name": "destinationChainId", "type": "uint32"}
        ],
        "name": "DepositInitiated",
        "type": "event"
    }
])

DESTINATION_TOKEN_ABI = json.dumps([
    {
        "constant": False,
        "inputs": [
            {"name": "recipient", "type": "address"},
            {"name": "amount", "type": "uint256"},
            {"name": "sourceTxHash", "type": "bytes32"}
        ],
        "name": "mint",
        "outputs": [],
        "type": "function"
    }
])

# --- Architectural Components ---

class BlockchainConnector:
    """
    Manages the connection to a blockchain node via Web3.py.
    Encapsulates the Web3 instance and handles connection health checks.
    This promotes separation of concerns, making it easy to swap out connection logic.
    """
    def __init__(self, rpc_url: str, chain_name: str):
        """
        Initializes the connector with a given RPC URL.

        Args:
            rpc_url (str): The HTTP RPC endpoint of the blockchain node.
            chain_name (str): A human-readable name for the chain (for logging).
        """
        self.rpc_url = rpc_url
        self.chain_name = chain_name
        self.web3: Optional[Web3] = None
        self.logger = logging.getLogger(self.__class__.__name__)

    def connect(self) -> None:
        """
        Establishes a connection to the blockchain node.
        Raises ConnectionError if the connection fails.
        """
        try:
            self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))
            if not self.web3.is_connected():
                raise ConnectionError(f"Failed to connect to {self.chain_name} at {self.rpc_url}")
            self.logger.info(f"Successfully connected to {self.chain_name} node.")
        except Exception as e:
            self.logger.error(f"Connection error for {self.chain_name}: {e}")
            self.web3 = None
            raise ConnectionError(f"Could not establish connection to {self.chain_name}.")

    def get_contract(self, address: str, abi: str) -> Optional[Contract]:
        """
        Returns a Web3.py Contract instance if connected.

        Args:
            address (str): The contract's checksummed address.
            abi (str): The contract's ABI in JSON string format.

        Returns:
            Optional[Contract]: A contract instance or None if not connected.
        """
        if not self.web3:
            self.logger.warning(f"Cannot get contract; not connected to {self.chain_name}.")
            return None
        return self.web3.eth.contract(address=address, abi=abi)

class EventScanner:
    """
    Scans a given blockchain for specific contract events within a block range.
    This component is responsible for querying the chain for new, relevant events.
    """
    def __init__(self, connector: BlockchainConnector):
        """
        Initializes the scanner with a blockchain connector.

        Args:
            connector (BlockchainConnector): The connector for the chain to be scanned.
        """
        self.connector = connector
        self.logger = logging.getLogger(self.__class__.__name__)

    def scan_for_events(self, contract: Contract, event_name: str, from_block: int, to_block: int) -> List[AttributeDict]:
        """
        Scans for events and handles potential issues like empty results or RPC errors.

        Args:
            contract (Contract): The Web3 contract instance to scan.
            event_name (str): The name of the event to look for (e.g., 'DepositInitiated').
            from_block (int): The starting block number for the scan.
            to_block (int): The ending block number for the scan.

        Returns:
            List[AttributeDict]: A list of found event logs.
        """
        self.logger.info(f"Scanning for '{event_name}' events on {self.connector.chain_name} from block {from_block} to {to_block}.")
        if from_block > to_block:
            self.logger.warning(f"'from_block' ({from_block}) cannot be greater than 'to_block' ({to_block}). Skipping scan.")
            return []
        
        try:
            event_filter = getattr(contract.events, event_name).create_filter(
                fromBlock=from_block,
                toBlock=to_block
            )
            events = event_filter.get_all_entries()
            if events:
                self.logger.info(f"Found {len(events)} new '{event_name}' event(s).")
            else:
                self.logger.info("No new events found in this range.")
            return events
        except (ValueError, BadFunctionCallOutput, ConnectionError) as e:
            self.logger.error(f"Failed to scan events on {self.connector.chain_name} due to an RPC error: {e}")
            # In a real system, this might trigger a fallback to a different RPC
            return []
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during event scanning: {e}")
            return []

class TransactionValidator:
    """
    Performs off-chain validation of a potential cross-chain transaction.
    This simulates checks that cannot be done on-chain, like calling external APIs
    or complex business logic.
    """
    MIN_DEPOSIT_AMOUNT = 10 * 10**18  # Minimum deposit of 10 tokens
    MAX_DEPOSIT_AMOUNT = 10000 * 10**18 # Maximum deposit of 10,000 tokens
    SUPPORTED_DESTINATION_CHAIN = 5 # A mock chain ID for the destination

    def __init__(self, explorer_api_url: str):
        """
        Initializes the validator.

        Args:
            explorer_api_url (str): The base URL for the block explorer API.
        """
        self.explorer_api_url = explorer_api_url
        self.logger = logging.getLogger(self.__class__.__name__)

    def validate_deposit(self, event: AttributeDict) -> bool:
        """
        Validates a deposit event against a set of rules.

        Args:
            event (AttributeDict): The event log to validate.

        Returns:
            bool: True if the deposit is valid, False otherwise.
        """
        tx_hash = event.transactionHash.hex()
        self.logger.info(f"Validating deposit from transaction {tx_hash}...")

        # 1. Business Logic Check: Amount
        amount = event.args.amount
        if not (self.MIN_DEPOSIT_AMOUNT <= amount <= self.MAX_DEPOSIT_AMOUNT):
            self.logger.warning(f"Validation FAILED for {tx_hash}: Amount {amount} is out of bounds.")
            return False

        # 2. Business Logic Check: Supported Destination
        if event.args.destinationChainId != self.SUPPORTED_DESTINATION_CHAIN:
            self.logger.warning(f"Validation FAILED for {tx_hash}: Unsupported destination chain ID {event.args.destinationChainId}.")
            return False
        
        # 3. External API Check: Transaction finality (simulated)
        # In a real system, you would check if the transaction has enough confirmations.
        try:
            params = {'module': 'transaction', 'action': 'gettxreceiptstatus', 'txhash': tx_hash}
            # In this simulation, we'll mock the response instead of a real API call
            # response = requests.get(self.explorer_api_url, params=params, timeout=10)
            # response.raise_for_status()
            # data = response.json()
            # if data.get('status') != '1':
            #    self.logger.warning(f"Validation FAILED for {tx_hash}: Transaction has failed on source chain.")
            #    return False

            # --- MOCK RESPONSE --- #
            mock_api_response = {'status': '1', 'message': 'OK', 'result': {'status': '1'}}
            self.logger.info(f"Simulated API check for {tx_hash}: Call to {self.explorer_api_url} successful.")
            if mock_api_response['result']['status'] != '1':
                 self.logger.warning(f"Validation FAILED for {tx_hash}: Transaction status is not '1' via explorer API.")
                 return False
            # --- END MOCK --- #

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Validation HALTED for {tx_hash}: Could not reach explorer API. Error: {e}")
            # A real system would retry this check later.
            return False

        self.logger.info(f"Validation PASSED for transaction {tx_hash}.")
        return True

class CrossChainProcessor:
    """
    The main orchestrator that uses other components to process cross-chain events.
    It maintains the state (last scanned block) and coordinates the flow from
    scanning to validation to execution on the destination chain.
    """
    def __init__(self, source_scanner: EventScanner, dest_connector: BlockchainConnector, validator: TransactionValidator):
        """
        Initializes the processor.

        Args:
            source_scanner (EventScanner): Scanner for the source chain.
            dest_connector (BlockchainConnector): Connector for the destination chain.
            validator (TransactionValidator): The off-chain transaction validator.
        """
        self.source_scanner = source_scanner
        self.dest_connector = dest_connector
        self.validator = validator
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # In a real application, this would be persisted to a database.
        self.last_scanned_block = 1_000_000 # Starting block for the simulation
        self.processed_nonces = set()
    
    def run_simulation_cycle(self) -> None:
        """
        Executes one full cycle of the event listening and processing logic.
        """
        self.logger.info(f"--- Starting new processing cycle --- ")
        
        # --- 1. Connect to Chains ---
        # These would typically be long-lived connections, but we reconnect for robustness in this simulation.
        try:
            self.source_scanner.connector.connect()
            self.dest_connector.connect()
        except ConnectionError:
            self.logger.error("Aborting cycle due to connection failure.")
            return
        
        # --- 2. Scan for Events ---
        source_bridge_contract = self.source_scanner.connector.get_contract(SOURCE_BRIDGE_CONTRACT_ADDRESS, SOURCE_BRIDGE_ABI)
        if not source_bridge_contract:
            self.logger.error("Could not get source bridge contract instance. Aborting cycle.")
            return

        # Simulate block progression
        current_block = self.last_scanned_block + random.randint(5, 10)
        
        # Mocked event finding logic. In a real scenario, `scan_for_events` would query the RPC.
        # Here, we inject a mock event to ensure the simulation is interesting.
        mock_events = self._get_mock_events(self.last_scanned_block + 1, current_block)
        
        # --- 3. Process Events ---
        if not mock_events:
            self.logger.info("No new events to process.")
        else:
            for event in mock_events:
                nonce = event.args.nonce
                if nonce in self.processed_nonces:
                    self.logger.warning(f"Skipping event with nonce {nonce} as it has already been processed.")
                    continue

                # --- 4. Validate Event ---
                is_valid = self.validator.validate_deposit(event)
                if is_valid:
                    # --- 5. Execute on Destination Chain (Simulated) ---
                    self.submit_mint_transaction(event)
                    self.processed_nonces.add(nonce)
                else:
                    self.logger.error(f"Event with nonce {nonce} failed validation. No mint transaction will be submitted.")

        # --- 6. Update State ---
        self.last_scanned_block = current_block
        self.logger.info(f"Cycle finished. Next scan will start from block {self.last_scanned_block + 1}.")

    def submit_mint_transaction(self, event: AttributeDict) -> None:
        """
        Simulates building, signing, and sending a 'mint' transaction to the destination chain.
        """
        if not self.dest_connector.web3:
            self.logger.error("Cannot submit mint tx: Destination chain not connected.")
            return

        dest_token_contract = self.dest_connector.get_contract(DESTINATION_TOKEN_CONTRACT_ADDRESS, DESTINATION_TOKEN_ABI)
        if not dest_token_contract:
             self.logger.error("Could not get destination token contract instance.")
             return

        recipient = event.args.recipient
        amount = event.args.amount
        source_tx_hash = event.transactionHash
        nonce = event.args.nonce

        self.logger.info(f"Preparing to mint {amount / 1e18} tokens for {recipient} on destination chain.")
        self.logger.info(f"Source Tx Hash for proof: {source_tx_hash.hex()}")

        # In a real application, you would build and sign the transaction here:
        # w3 = self.dest_connector.web3
        # relayer_account = w3.eth.account.from_key(RELAYER_PRIVATE_KEY)
        # tx = dest_token_contract.functions.mint(recipient, amount, source_tx_hash).build_transaction({
        #     'from': relayer_account.address,
        #     'nonce': w3.eth.get_transaction_count(relayer_account.address),
        #     'gas': 200000,
        #     'gasPrice': w3.eth.gas_price
        # })
        # signed_tx = w3.eth.account.sign_transaction(tx, RELAYER_PRIVATE_KEY)
        # tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        # self.logger.info(f"Submitted mint transaction to destination chain. Tx Hash: {tx_hash.hex()}")

        # For simulation, we just log the action.
        simulated_dest_tx_hash = "0x" + os.urandom(32).hex()
        self.logger.info(f"[SIMULATION] Mint transaction successfully submitted. Destination Tx Hash: {simulated_dest_tx_hash}")

    def _get_mock_events(self, from_block: int, to_block: int) -> List[AttributeDict]:
        """
A helper to generate mock events for the simulation.
        """
        self.logger.info(f"Simulating event scan from block {from_block} to {to_block}.")
        # Only generate an event 1 in 3 cycles to make it more realistic.
        if random.random() < 0.66:
            self.logger.info("[SIMULATION] No new events found in this range.")
            return []

        mock_event = AttributeDict({
            'args': AttributeDict({
                'sender': Web3.to_checksum_address("0xSender010101010101010101010101010101010101"),
                'recipient': Web3.to_checksum_address("0xRecipient02020202020202020202020202020202"),
                'amount': random.randint(5, 20000) * 10**18, # Random valid/invalid amount
                'nonce': from_block, # Use block number as a unique nonce
                'destinationChainId': 5
            }),
            'transactionHash': os.urandom(32),
            'blockNumber': from_block + 1
        })
        self.logger.info(f"[SIMULATION] Found 1 mock 'DepositInitiated' event in block {mock_event.blockNumber}.")
        return [mock_event]


if __name__ == "__main__":
    """
    Main execution block to run the simulation.
    """
    print("==========================================================")
    print("===   Cross-Chain Bridge Event Listener Simulation   ===")
    print("==========================================================\n")

    # 1. Initialize components
    source_connector = BlockchainConnector(SOURCE_CHAIN_RPC_URL, "SourceChain")
    dest_connector = BlockchainConnector(DESTINATION_CHAIN_RPC_URL, "DestinationChain")
    
    event_scanner = EventScanner(source_connector)
    validator = TransactionValidator(MOCK_EXPLORER_API_URL)
    
    processor = CrossChainProcessor(
        source_scanner=event_scanner,
        dest_connector=dest_connector,
        validator=validator
    )

    # 2. Run the simulation loop
    try:
        cycle_count = 0
        while cycle_count < 5: # Run for 5 cycles for a short demonstration
            processor.run_simulation_cycle()
            print("\n") # Add space between cycles
            time.sleep(3) # Wait between cycles to simulate real-world polling
            cycle_count += 1
    except KeyboardInterrupt:
        print("\nSimulation stopped by user.")
    except Exception as e:
        logging.critical(f"A critical error occurred in the main loop: {e}")
    
    print("==========================================================")
    print("===              Simulation Complete                 ===")
    print("==========================================================\n")
