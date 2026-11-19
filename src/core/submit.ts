/**
 * Submit signed Ethereum transactions to blockchain
 */

import { parseTransaction, recoverTransactionAddress, type Hex, type TransactionSerialized } from 'viem';
import { CHAIN_RPC_URLS, EXPLORER_URLS } from './constants';
import { createRpcClient } from './rpc';

export interface SubmitOptions {
  signedTransaction: string;
  rpcUrl?: string;
  chainId?: number;
  waitForConfirmation?: boolean;
}

export interface SubmitResult {
  txHash: string;
  blockNumber?: number;
  confirmations?: number;
  status?: number;
}

/**
 * Submits a signed transaction to the blockchain
 */
export async function submitTransaction(
  options: SubmitOptions
): Promise<SubmitResult> {
  const { signedTransaction, rpcUrl, chainId, waitForConfirmation = false } = options;
  
  // Determine RPC URL
  let providerUrl: string;
  
  if (rpcUrl) {
    providerUrl = rpcUrl;
  } else if (chainId && CHAIN_RPC_URLS[chainId]) {
    providerUrl = CHAIN_RPC_URLS[chainId];
  } else {
    throw new Error(
      `RPC URL required. Either provide --rpc-url or use a known chain ID. ` +
      `Known chain IDs: ${Object.keys(CHAIN_RPC_URLS).join(', ')}`
    );
  }
  
  const client = createRpcClient(providerUrl);

  try {
    // Broadcast the signed transaction
    const txHash = await client.sendRawTransaction({ serializedTransaction: signedTransaction as Hex });

    console.log(`\n✓ Transaction submitted successfully!`);
    console.log(`  Transaction Hash: ${txHash}`);
    console.log(`  Explorer: ${getExplorerUrl(chainId, txHash)}`);

    if (!waitForConfirmation) {
      return { txHash };
    }

    // Wait for the transaction receipt (included in a block)
    console.log('⏳ Waiting for transaction confirmation...');
    const receipt = await client.waitForTransactionReceipt({ hash: txHash });

    // Get current block number to calculate confirmations
    const currentBlock = await client.getBlockNumber();
    const blockNumber = Number(receipt.blockNumber);

    return {
      txHash: receipt.transactionHash,
      blockNumber,
      confirmations: Number(currentBlock - receipt.blockNumber + 1n),
      status: receipt.status === 'success' ? 1 : 0,
    };
  } catch (error: any) {
    const errorMessage = error.shortMessage || error.reason || error.message || String(error);
    throw new Error(`Transaction failed: ${errorMessage}`);
  }
}

/**
 * Decodes a signed transaction to extract the signer address
 */
export async function getSignerAddress(signedTransaction: string, _chainId?: number): Promise<string | undefined> {
  try {
    const serializedTransaction = signedTransaction as TransactionSerialized;
    // make sure the payload is a well-formed transaction before recovering the signer
    parseTransaction(serializedTransaction);
    return await recoverTransactionAddress({ serializedTransaction });
  } catch (error) {
    // If decoding fails, return undefined
    return undefined;
  }
}

/**
 * Gets explorer URL for a transaction
 */
function getExplorerUrl(chainId?: number, txHash?: string): string {
  if (!chainId || !txHash) return 'N/A';
  
  const explorerBase = EXPLORER_URLS[chainId];
  return explorerBase ? `${explorerBase}${txHash}` : `Chain ID ${chainId} (no explorer configured)`;
}

