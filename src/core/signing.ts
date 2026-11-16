/**
 * Ethereum Transaction Signing with AWS KMS
 * 
 * Uses KMS ECC_SECG_P256K1 key to sign Ethereum transactions natively.
 * Private key never leaves KMS - signing happens in HSM!
 */

import { SignCommand, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import {
  getAddress,
  keccak256,
  parseEther,
  recoverAddress,
  serializeTransaction,
  toBytes,
  toHex,
  type Hex,
  type TransactionSerializable,
} from 'viem';
import { createKMSClient } from './kms-client';
import { createRpcClient } from './rpc';
import { CHAIN_RPC_URLS } from './constants';

const DEFAULT_GAS_PRICE = '1000000000'; // 1 gwei

/**
 * Converts a decimal or 0x-prefixed numeric string (or number) to a 0x-prefixed hex quantity
 */
function toQuantity(value: string | number | bigint): Hex {
  return toHex(BigInt(value));
}

function getDefaultRpcUrl(chainId?: number): string | undefined {
  return chainId ? CHAIN_RPC_URLS[chainId] : undefined;
}

/**
 * Fetches nonce from network if not provided
 */
async function fetchNonceIfNeeded(
  keyId: string,
  transaction: EthereumTransaction,
  tx: any,
  region?: string
): Promise<void> {
  if (transaction.nonce !== undefined) {
    tx.nonce = transaction.nonce;
    return;
  }

  if (transaction.rpcUrl || transaction.chainId) {
    try {
      const rpcUrl = transaction.rpcUrl || getDefaultRpcUrl(transaction.chainId);
      if (rpcUrl) {
        const client = createRpcClient(rpcUrl);
        const senderAddress = await getEthereumAddress(keyId, region);
        tx.nonce = await client.getTransactionCount({ address: senderAddress as Hex, blockTag: 'pending' });
        return;
      }
    } catch (error: any) {
      console.warn(`Warning: Could not fetch nonce from network: ${error.message}`);
    }
  }
  
  tx.nonce = 0;
}

/**
 * Gets the public key from KMS in hex format
 */
export async function getPublicKey(keyId: string, region?: string): Promise<string> {
  const kmsClient = createKMSClient(region);
  
  try {
    const getPublicKeyCommand = new GetPublicKeyCommand({ KeyId: keyId });
    const response = await kmsClient.send(getPublicKeyCommand);
    
    if (!response.PublicKey) {
      throw new Error('Failed to get public key from KMS');
    }
  
    const publicKeyBytes = Buffer.from(response.PublicKey);
    
    // AWS KMS returns public key in DER format (ASN.1)
    // We need to parse it to extract the raw public key
    // Format: SEQUENCE { AlgorithmIdentifier, BIT STRING { 0x04 [64 bytes] } }
    
    let publicKey: Buffer;
    
    if (publicKeyBytes[0] === 0x04) {
      // Raw format (uncompressed) - first byte is 0x04
      publicKey = publicKeyBytes;
    } else if (publicKeyBytes[0] === 0x30) {
      // DER format - need to parse
      // Look for the bit string (0x03) that contains the public key
      let offset = 0;
      
      // Skip outer SEQUENCE (0x30)
      if (publicKeyBytes[offset] === 0x30) {
        offset += 2; // Skip 0x30 and length byte
        
        // Skip AlgorithmIdentifier (OID for secp256k1)
        // Find the BIT STRING (0x03)
        while (offset < publicKeyBytes.length && publicKeyBytes[offset] !== 0x03) {
          offset++;
        }
        
        if (publicKeyBytes[offset] === 0x03) {
          // Found BIT STRING
          const bitStringLength = publicKeyBytes[offset + 1];
          offset += 2; // Skip 0x03 and length
          
          // The first byte of the bit string is usually 0x00 (unused bits), 
          // followed by 0x04 (uncompressed point), then 64 bytes
          if (publicKeyBytes[offset] === 0x00 && publicKeyBytes[offset + 1] === 0x04) {
            // Extract the public key (0x04 + 64 bytes = 65 bytes)
            publicKey = publicKeyBytes.slice(offset + 1, offset + 66);
          } else if (publicKeyBytes[offset] === 0x04) {
            // No padding byte, 0x04 directly
            publicKey = publicKeyBytes.slice(offset, offset + 65);
          } else {
            throw new Error('Unexpected DER format: could not find public key');
          }
        } else {
          throw new Error('Unexpected DER format: BIT STRING not found');
        }
      } else {
        throw new Error('Unexpected public key format: not raw or DER');
      }
    } else {
      throw new Error(`Unexpected public key format: starts with 0x${publicKeyBytes[0].toString(16)}`);
    }
    
    // Verify it's uncompressed format (starts with 0x04)
    if (publicKey[0] !== 0x04) {
      throw new Error(`Unexpected public key format: expected 0x04, got 0x${publicKey[0].toString(16)}`);
    }
    
    // Return uncompressed public key (0x04 prefix + 64 bytes = 130 hex chars)
    return '0x' + publicKey.toString('hex');
  } catch (error: any) {
    const errorMessage = error.message || error.name || 'Unknown error';
    const errorCode = error.$metadata?.httpStatusCode || error.Code || '';
    throw new Error(`Failed to get public key: ${errorMessage}${errorCode ? ` (Code: ${errorCode})` : ''}`);
  }
}

/**
 * Gets Ethereum address from KMS public key
 */
export async function getEthereumAddress(keyId: string, region?: string): Promise<string> {
  const publicKeyHex = await getPublicKey(keyId, region);
  
  // publicKeyHex is in format: 0x04[64 bytes]
  // Remove 0x prefix and 0x04 prefix to get the 64-byte public key
  const publicKeyBytes = publicKeyHex.slice(4); // Remove '0x04'
  
  // Hash the public key (64 bytes) with Keccak256
  const hash = keccak256(('0x' + publicKeyBytes) as Hex);
  
  // Take the last 20 bytes (40 hex characters) as the address
  const address = getAddress('0x' + hash.slice(-40));
  
  return address;
}

export interface EthereumTransaction {
  to: string;
  value?: string;
  data?: string;
  nonce?: number;
  gasLimit?: string;
  gasPrice?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  chainId?: number;
  rpcUrl?: string; // Optional RPC URL for gas estimation
}

/**
 * Signs an Ethereum transaction using KMS
 */
export async function signTransaction(
  keyId: string,
  transaction: EthereumTransaction,
  region?: string
): Promise<string> {
  console.log('signTransaction', transaction);
  const kmsClient = createKMSClient(region);
  
  // Build transaction object with proper types
  const tx: any = {
    to: transaction.to as string,
    chainId: transaction.chainId,
  };
  
  if (transaction.value) {
    tx.value = parseEther(transaction.value).toString();
  }
  if (transaction.data) {
    // Ensure data is a hex string with 0x prefix
    tx.data = transaction.data.startsWith('0x') ? transaction.data : '0x' + transaction.data;
  }
  
  // Fetch nonce if not provided
  await fetchNonceIfNeeded(keyId, transaction, tx, region);

  // Handle gas limit
  if (transaction.gasLimit) {
    tx.gasLimit = transaction.gasLimit;
  } else if (transaction.rpcUrl || transaction.chainId) {
    try {
      const rpcUrl = transaction.rpcUrl || getDefaultRpcUrl(transaction.chainId);
      if (rpcUrl) {
        const client = createRpcClient(rpcUrl);
        const estimatedGas = await client.estimateGas({
          to: transaction.to as Hex,
          value: transaction.value ? parseEther(transaction.value) : undefined,
          data: tx.data,
        });
        tx.gasLimit = (estimatedGas * 2n).toString();
      } else {
        tx.gasLimit = '21000'; // Default gas limit for simple transfer
      }
    } catch (error: any) {
      console.warn(`Warning: Could not fetch gas data from network: ${error.message}`);
      tx.gasLimit = '21000'; // Default gas limit for simple transfer
    }
  } else {
    tx.gasLimit = '21000'; // Default gas limit for simple transfer
  }

  // Determine if we should use EIP-1559 or legacy transaction
  // Only use EIP-1559 if both maxFeePerGas and maxPriorityFeePerGas are explicitly provided
  // Otherwise, use legacy transactions
  const useEIP1559 = !!(transaction.maxFeePerGas && transaction.maxPriorityFeePerGas);
  
  // Handle gas fees (EIP-1559 or legacy)
  if (useEIP1559) {
    // EIP-1559 transaction - both fields must be provided
    tx.maxFeePerGas = transaction.maxFeePerGas!;
    tx.maxPriorityFeePerGas = transaction.maxPriorityFeePerGas!;
  } else {
    // Legacy transaction - use gasPrice
    if (transaction.gasPrice) {
      tx.gasPrice = transaction.gasPrice;
    } else if (transaction.rpcUrl || transaction.chainId) {
      try {
        const rpcUrl = transaction.rpcUrl || getDefaultRpcUrl(transaction.chainId);
        if (rpcUrl) {
          const client = createRpcClient(rpcUrl);
          const gasPrice = await client.getGasPrice();
          tx.gasPrice = gasPrice.toString();
        } else {
          tx.gasPrice = DEFAULT_GAS_PRICE;
        }
      } catch (error: any) {
        console.warn(`Warning: Could not fetch gas data from network: ${error.message}`);
        tx.gasPrice = DEFAULT_GAS_PRICE;
      }
    } else {
      tx.gasPrice = DEFAULT_GAS_PRICE;
    }
  }
  
  const chainId = tx.chainId;
  if (chainId === undefined || chainId === null) {
    throw new Error('chainId is required to sign a transaction');
  }

  // Prepare common transaction fields (ensure consistent format)
  const toAddress = tx.to ? ((tx.to.startsWith('0x') ? tx.to : '0x' + tx.to) as Hex) : undefined;
  const commonFields = {
    chainId: Number(chainId),
    nonce: Number(tx.nonce !== undefined ? tx.nonce : 0),
    gas: BigInt(tx.gasLimit || '0x5208'),
    to: toAddress,
    value: BigInt(tx.value || 0),
    data: (tx.data || '0x') as Hex,
  };

  // EIP-1559 (type 2) or legacy (EIP-155) transaction
  const unsignedTx: TransactionSerializable = useEIP1559
    ? {
        type: 'eip1559',
        ...commonFields,
        maxFeePerGas: BigInt(tx.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(tx.maxPriorityFeePerGas),
      }
    : {
        type: 'legacy',
        ...commonFields,
        gasPrice: BigInt(tx.gasPrice || 0),
      };

  // The hash to sign is the keccak256 of the unsigned serialized transaction (32 bytes, as required by KMS ECDSA_SHA_256 digests)
  const messageHash = toBytes(keccak256(serializeTransaction(unsignedTx)));

  // Ensure we have exactly 32 bytes for KMS (ECDSA_SHA_256 requires 32-byte digest)
  if (messageHash.length !== 32) {
    throw new Error(`Invalid message hash length: expected 32 bytes, got ${messageHash.length}`);
  }
  
  // Sign with KMS
  const signCommand = new SignCommand({
    KeyId: keyId,
    Message: messageHash,
    MessageType: 'DIGEST',
    SigningAlgorithm: 'ECDSA_SHA_256',
  });
  
  const signResponse = await kmsClient.send(signCommand);
  
  if (!signResponse.Signature) {
    throw new Error('Failed to sign transaction with KMS');
  }
  
  // Convert KMS signature (DER format) to Ethereum format
  // KMS returns DER-encoded signature, we need to parse it to get r and s
  const derSignature = Buffer.from(signResponse.Signature);
  
  // Parse DER signature to get r and s values
  // DER format: 0x30 [length] 0x02 [r-length] [r] 0x02 [s-length] [s]
  let offset = 0;
  
  // Check for SEQUENCE (0x30)
  if (derSignature[offset] !== 0x30) {
    throw new Error('Invalid DER signature: expected SEQUENCE (0x30)');
  }
  offset += 2; // Skip 0x30 and length byte
  
  // Parse r value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER (0x02) for r');
  }
  const rLength = derSignature[offset + 1];
  let rStart = offset + 2;
  
  // Handle leading zero padding (DER allows leading zeros to indicate positive number)
  if (derSignature[rStart] === 0x00 && rLength > 1) {
    rStart++;
  }
  const r = derSignature.slice(rStart, offset + 2 + rLength);
  offset += 2 + rLength;
  
  // Parse s value
  if (offset >= derSignature.length || derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER (0x02) for s');
  }
  const sLength = derSignature[offset + 1];
  let sStart = offset + 2;
  
  // Handle leading zero padding
  if (derSignature[sStart] === 0x00 && sLength > 1) {
    sStart++;
  }
  const s = derSignature.slice(sStart, offset + 2 + sLength);
  
  // Ensure r and s are 32 bytes (pad with zeros at the start if needed)
  const rPadded = Buffer.alloc(32);
  const sPadded = Buffer.alloc(32);
  
  // Copy r and s to the end of the 32-byte buffers (right-align)
  const rOffset = Math.max(0, 32 - r.length);
  const sOffset = Math.max(0, 32 - s.length);
  r.copy(rPadded, rOffset);
  s.copy(sPadded, sOffset);
  
  // Convert to BigInt to check if s is canonical
  // secp256k1 curve order: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  const sBigInt = BigInt('0x' + sPadded.toString('hex'));
  
  // Ensure s is in canonical form (s <= n/2)
  // Ethereum requires canonical (low) s values, so we must flip it if needed
  const sCanonical = sBigInt > SECP256K1_N / 2n
    ? Buffer.from((SECP256K1_N - sBigInt).toString(16).padStart(64, '0'), 'hex')
    : sPadded;
  
  // Create signature buffers
  const rBuffer = rPadded;
  const sBuffer = sCanonical;
  
  // Get the expected Ethereum address from KMS to verify the correct recovery ID
  const expectedAddress = await getEthereumAddress(keyId, region);
  const expectedAddressLower = expectedAddress.toLowerCase();
  
  // Find the correct yParity by checking which one recovers the KMS key's address
  const rHex = ('0x' + rBuffer.toString('hex')) as Hex;
  const sHex = ('0x' + sBuffer.toString('hex')) as Hex;
  let lastError: Error | null = null;

  for (const yParity of [0, 1]) {
    try {
      const recoveredAddress = await recoverAddress({
        hash: toHex(messageHash),
        signature: { r: rHex, s: sHex, yParity },
      });

      if (recoveredAddress.toLowerCase() === expectedAddressLower) {
        // legacy transactions carry the EIP-155 `v` (chainId * 2 + 35 + yParity); typed transactions carry yParity
        return serializeTransaction(
          unsignedTx,
          useEIP1559
            ? { r: rHex, s: sHex, yParity }
            : { r: rHex, s: sHex, v: BigInt(Number(chainId) * 2 + 35 + yParity) }
        );
      }
    } catch (error: any) {
      console.log('signature recovery warning: ', error);
      lastError = error;
    }
  }

  // If we get here, none of the recovery IDs produced a matching address
  const errorMsg = lastError 
    ? `Could not construct signed transaction with matching address: ${lastError.message}` 
    : `Could not construct signed transaction: no recovery ID produced address ${expectedAddress}`;
  throw new Error(errorMsg);
}

/**
 * Signs a message using KMS
 */
export async function signMessage(
  keyId: string,
  message: string,
  region?: string
): Promise<string> {
  const kmsClient = createKMSClient(region);
  
  // Create Ethereum message hash (EIP-191)
  // Format: \x19Ethereum Signed Message:\n<length in bytes><message>
  const messageBuffer = Buffer.from(message, 'utf8');
  const prefix = Buffer.from('\x19Ethereum Signed Message:\n' + messageBuffer.length.toString(), 'utf8');
  const messageToHash = Buffer.concat([prefix, messageBuffer]);
  const messageBytes = Buffer.from(keccak256(toHex(messageToHash)).slice(2), 'hex');
  
  // Sign with KMS
  const signCommand = new SignCommand({
    KeyId: keyId,
    Message: messageBytes,
    MessageType: 'DIGEST',
    SigningAlgorithm: 'ECDSA_SHA_256',
  });
  
  const signResponse = await kmsClient.send(signCommand);
  
  if (!signResponse.Signature) {
    throw new Error('Failed to sign message with KMS');
  }
  
  // Convert signature to hex
  return '0x' + Buffer.from(signResponse.Signature).toString('hex');
}

