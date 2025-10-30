# Scale: Cross-Chain Bridge Event Listener Simulation

This repository contains a Python-based simulation of a crucial off-chain component for a cross-chain bridge. It acts as a "relayer" or "validator node" that listens for events on a source blockchain and triggers corresponding actions on a destination blockchain.

This script is designed to be architecturally sound, demonstrating principles like separation of concerns, error handling, and interaction with external services, all within a simulated environment.

## Concept

A cross-chain bridge allows users to transfer assets or data from one blockchain (the "source chain") to another (the "destination chain"). A common pattern for this is:

1.  A user deposits assets into a smart contract on the source chain. This action emits an event (e.g., `DepositInitiated`).
2.  A network of off-chain listeners (relayers/validators) detects this event.
3.  These listeners validate the deposit to ensure it's legitimate (e.g., has enough confirmations, is within value limits, etc.).
4.  Once validated, a listener submits a transaction to a smart contract on the destination chain to mint a corresponding amount of a "wrapped" asset for the user.

This simulation models the off-chain listener (steps 2, 3, and 4), which is the backbone of the bridge's security and operation.

## Code Architecture

The script is designed with a modular, class-based architecture to ensure clarity, testability, and maintainability. Each class has a distinct responsibility:

-   `BlockchainConnector`: This class is responsible for managing the connection to a blockchain node using `web3.py`. It encapsulates the `Web3` instance and provides a clean interface for connecting and instantiating contract objects. It handles connection errors gracefully.

-   `EventScanner`: Its sole purpose is to scan a given range of blocks on a blockchain for a specific event from a specific smart contract. It uses a `BlockchainConnector` to communicate with the node.

-   `TransactionValidator`: This component performs off-chain validation checks on a detected event. This is where business logic and security rules are enforced. In this simulation, it checks:
    -   If the deposit amount is within acceptable limits.
    -   If the destination chain is supported.
    -   **(Simulated)** It makes an API call using the `requests` library to a mock block explorer to verify the transaction's finality.

-   `CrossChainProcessor`: This is the main orchestrator. It ties all the other components together. It maintains the state of the listener (e.g., the last block it scanned) and controls the overall workflow:
    1.  Uses the `EventScanner` to find new events.
    2.  For each event, it uses the `TransactionValidator` to verify it.
    3.  If valid, it simulates the creation, signing, and submission of a `mint` transaction on the destination chain using the `BlockchainConnector`.

This separation of concerns makes the system robust. For example, the `BlockchainConnector` could be extended to support WebSocket providers or multiple fallback RPCs without changing the `EventScanner`'s logic.

## How it Works

The script runs a continuous simulation loop, with each iteration representing a single processing cycle. Here's a step-by-step breakdown:

1.  **Initialization**: The script starts by instantiating all the necessary classes: `BlockchainConnector` for both chains, `EventScanner`, `TransactionValidator`, and the main `CrossChainProcessor`.

2.  **Start Cycle**: The `CrossChainProcessor` begins a cycle. It first ensures it can connect to both the source and destination chains.

3.  **Scan for Events**: The processor determines the block range to scan (from the last scanned block to the simulated current block). It then instructs the `EventScanner` to look for `DepositInitiated` events within this range on the source chain.

4.  **Event Generation (Simulation)**: To make the script runnable without a live blockchain, the `run_simulation_cycle` method includes a helper (`_get_mock_events`) that randomly generates a mock `DepositInitiated` event. In a real-world scenario, this part would be replaced by the actual results from the `EventScanner`'s RPC call.

5.  **Validation**: If an event is found, it's passed to the `TransactionValidator`. The validator checks its internal rules. Crucially, it simulates an API call to a mock Etherscan-like service to confirm the transaction's status. This demonstrates interaction with external, off-chain data sources.

6.  **Minting (Simulation)**: If validation is successful, the `CrossChainProcessor` proceeds to the final step. It simulates building and signing a `mint` transaction for the destination chain. It logs the details of the simulated transaction, including the recipient, amount, and a new simulated transaction hash.

7.  **State Update**: The processor updates its `last_scanned_block` state variable so the next cycle knows where to resume scanning. This prevents reprocessing old events.

8.  **Wait**: The script waits for a few seconds before starting the next cycle, mimicking the polling interval of a real-world listener.

## Usage

### Running the Simulation

Follow these steps to run the simulation.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/scale.git
    cd scale
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    # On Windows
    # venv\Scripts\activate
    # On macOS/Linux
    # source venv/bin/activate
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the script:**
    ```bash
    python script.py
    ```

**Expected Output:**

You will see a detailed log of the simulation's activity, showing each step of the process. The output will vary slightly due to the random generation of events and deposit amounts.

```
==========================================================
===   Cross-Chain Bridge Event Listener Simulation   ===
==========================================================

2023-10-27 10:30:00 - INFO - [CrossChainProcessor] - --- Starting new processing cycle --- 
2023-10-27 10:30:00 - INFO - [BlockchainConnector] - Successfully connected to SourceChain node.
2023-10-27 10:30:00 - INFO - [BlockchainConnector] - Successfully connected to DestinationChain node.
2023-10-27 10:30:00 - INFO - [CrossChainProcessor] - [SIMULATION] Found 1 mock 'DepositInitiated' event in block 1000002.
2023-10-27 10:30:00 - INFO - [TransactionValidator] - Validating deposit from transaction 0x...
2023-10-27 10:30:00 - INFO - [TransactionValidator] - Simulated API check for 0x...: Call to https://api.mock-source-scan.io/api successful.
2023-10-27 10:30:00 - INFO - [TransactionValidator] - Validation PASSED for transaction 0x...
2023-10-27 10:30:00 - INFO - [CrossChainProcessor] - Preparing to mint 15000.0 tokens for 0xRecipient0202... on destination chain.
2023-10-27 10:30:00 - INFO - [CrossChainProcessor] - Source Tx Hash for proof: 0x...
2023-10-27 10:30:00 - INFO - [CrossChainProcessor] - [SIMULATION] Mint transaction successfully submitted. Destination Tx Hash: 0x...
2023-10-27 10:30:00 - INFO - [CrossChainProcessor] - Cycle finished. Next scan will start from block 1000011.

... (The simulation continues for a few more cycles)
```

### Core Logic Snippet

The core of the simulation's setup in `script.py` demonstrates how the different architectural components are wired together:

```python
if __name__ == "__main__":
    # 1. Initialize connectors for source and destination chains
    source_chain_connector = BlockchainConnector(
        chain_name="SourceChain",
        rpc_url="https://mock.source.rpc"
    )
    dest_chain_connector = BlockchainConnector(
        chain_name="DestinationChain",
        rpc_url="https://mock.dest.rpc"
    )

    # 2. Set up the event scanner for the source chain
    event_scanner = EventScanner(source_chain_connector)

    # 3. Initialize the transaction validator with its rules
    validator = TransactionValidator(
        api_endpoint="https://api.mock-source-scan.io/api",
        min_amount=100,
        max_amount=100000
    )

    # 4. Create the main processor to orchestrate the workflow
    processor = CrossChainProcessor(
        source_connector=source_chain_connector,
        dest_connector=dest_chain_connector,
        event_scanner=event_scanner,
        validator=validator
    )

    # 5. Run the simulation loop
    processor.run_simulation(start_block=1000000, cycles=5)
```