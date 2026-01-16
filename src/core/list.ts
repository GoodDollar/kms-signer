/**
 * AWS KMS Key Listing
 * 
 * Functions to list and describe KMS keys
 */

import { 
  ListKeysCommand,
  DescribeKeyCommand,
  ListAliasesCommand,
  ListResourceTagsCommand,
} from '@aws-sdk/client-kms';
import { createKMSClient } from './kms-client';

export interface KeyInfo {
  keyId: string;
  keyArn: string;
  alias?: string;
  description?: string;
  keySpec?: string;
  keyUsage?: string;
  keyState?: string;
  creationDate?: Date;
  enabled?: boolean;
  tags?: Record<string, string>;
}

/**
 * Lists all KMS keys in the specified region
 * 
 * @param region - AWS region (defaults to AWS_REGION env var or us-east-1)
 * @param includeDetails - Whether to include detailed information for each key (default: true)
 * @param tagFilter - Optional filter by tag key and value. If provided, only keys matching the tag will be returned.
 * @returns Array of key information
 */
export async function listKMSKeys(
  region?: string,
  includeDetails: boolean = true,
  tagFilter?: { key: string; value: string }
): Promise<KeyInfo[]> {
  const kmsClient = createKMSClient(region);
  const keys: KeyInfo[] = [];
  
  try {
    // List all keys
    const listKeysCommand = new ListKeysCommand({});
    const listKeysResponse = await kmsClient.send(listKeysCommand);
    
    if (!listKeysResponse.Keys || listKeysResponse.Keys.length === 0) {
      return [];
    }

    // Get all aliases to map them to keys
    const listAliasesCommand = new ListAliasesCommand({});
    const aliasesResponse = await kmsClient.send(listAliasesCommand);
    const aliasMap = new Map<string, string>();
    
    if (aliasesResponse.Aliases) {
      for (const alias of aliasesResponse.Aliases) {
        if (alias.TargetKeyId && alias.AliasName) {
          aliasMap.set(alias.TargetKeyId, alias.AliasName);
        }
      }
    }

    // Helper function to fetch tags for a key
    const fetchTags = async (keyId: string): Promise<Record<string, string> | undefined> => {
      try {
        const listTagsCommand = new ListResourceTagsCommand({ KeyId: keyId });
        const tagsResponse = await kmsClient.send(listTagsCommand);
        
        if (tagsResponse.Tags && tagsResponse.Tags.length > 0) {
          const tags: Record<string, string> = {};
          tagsResponse.Tags.forEach(tag => {
            if (tag.TagKey && tag.TagValue !== undefined) {
              tags[tag.TagKey] = tag.TagValue;
            }
          });
          return tags;
        }
        return undefined;
      } catch (tagError: any) {
        // If we can't list tags (e.g., no permissions), return undefined
        return undefined;
      }
    };

    // Helper function to check if key matches tag filter
    const matchesTagFilter = (tags: Record<string, string> | undefined): boolean => {
      if (!tagFilter) return true;
      if (!tags) return false;
      return tags[tagFilter.key] === tagFilter.value;
    };

    // If tag filter is specified, fetch tags first and filter early
    // This avoids fetching unnecessary details for non-matching keys
    // Store tags in a map to avoid fetching them twice
    const tagsCache = new Map<string, Record<string, string> | undefined>();
    const allKeys = listKeysResponse.Keys || [];
    
    const keysToProcess = tagFilter 
      ? await (async () => {
          const matchingKeys: typeof allKeys = [];
          // Fetch tags in parallel for better performance
          const tagPromises = allKeys
            .filter(key => key.KeyId)
            .map(async (key) => {
              const tags = await fetchTags(key.KeyId!);
              tagsCache.set(key.KeyId!, tags);
              return { key, tags };
            });
          
          const results = await Promise.all(tagPromises);
          for (const { key, tags } of results) {
            if (matchesTagFilter(tags)) {
              matchingKeys.push(key);
            }
          }
          return matchingKeys;
        })()
      : allKeys;

    // Get details for each key if requested
    for (const key of keysToProcess) {
      if (!key.KeyId) continue;

      const keyInfo: KeyInfo = {
        keyId: key.KeyId,
        keyArn: key.KeyArn || '',
        alias: aliasMap.get(key.KeyId),
      };

      // Use cached tags if available, otherwise fetch them
      if (tagsCache.has(key.KeyId)) {
        keyInfo.tags = tagsCache.get(key.KeyId);
      }

      if (includeDetails) {
        try {
          const describeCommand = new DescribeKeyCommand({
            KeyId: key.KeyId,
          });
          const describeResponse = await kmsClient.send(describeCommand);
          
          if (describeResponse.KeyMetadata) {
            const metadata = describeResponse.KeyMetadata;
            keyInfo.description = metadata.Description;
            keyInfo.keySpec = metadata.KeySpec;
            keyInfo.keyUsage = metadata.KeyUsage;
            keyInfo.keyState = metadata.KeyState;
            keyInfo.creationDate = metadata.CreationDate;
            keyInfo.enabled = metadata.Enabled;
          }

          // Fetch tags if not already cached
          if (!keyInfo.tags) {
            keyInfo.tags = await fetchTags(key.KeyId);
          }
        } catch (error: any) {
          // If we can't describe the key (e.g., no permissions), just skip details
          console.warn(`Warning: Could not describe key ${key.KeyId}: ${error.message}`);
        }
      } else if (!keyInfo.tags && !tagFilter) {
        // Fetch tags even if not including details (unless filtering, where tags are already cached)
        keyInfo.tags = await fetchTags(key.KeyId);
      }

      keys.push(keyInfo);
    }

    return keys;
  } catch (error: any) {
    throw new Error(`Failed to list KMS keys: ${error.message}`);
  }
}

