/**
 * Minimal JSON-RPC client factory (viem)
 */

import { createPublicClient, http, webSocket, type PublicClient } from 'viem';

/**
 * Creates a read/submit client for an RPC endpoint. `ws://` and `wss://` URLs use a WebSocket transport,
 * everything else uses HTTP(S).
 */
export function createRpcClient(rpcUrl: string): PublicClient {
  const transport = /^wss?:\/\//i.test(rpcUrl) ? webSocket(rpcUrl) : http(rpcUrl);
  return createPublicClient({ transport });
}
