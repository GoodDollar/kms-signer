#!/usr/bin/env node

/**
 * CLI: Import existing Ethereum private key into AWS KMS
 */

import { importKMSKey } from '../core/setup';
import { getEthereumAddress } from '../core/signing';

async function main() {
  const privateKeyHex = process.argv[2];
  const aliasName = process.argv[3] || 'ethereum-signing-key-imported';
  const region = process.env.AWS_REGION || 'us-east-1';
  
  if (!privateKeyHex) {
    console.error('Usage: npm run import <PRIVATE_KEY_HEX> [ALIAS_NAME] [TAG_KEY1=TAG_VALUE1] [TAG_KEY2=TAG_VALUE2] ...');
    console.error('');
    console.error('Examples:');
    console.error('  npm run import 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
    console.error('  npm run import 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef my-key');
    console.error('  npm run import 0x1234... my-key Project=MyProject Team=DevOps');
    console.error('');
    console.error('Tags can also be provided via KMS_TAGS environment variable (JSON format):');
    console.error('  KMS_TAGS=\'[{"TagKey":"Project","TagValue":"MyProject"}]\' npm run import 0x1234...');
    console.error('');
    console.error('Note: The private key can be provided with or without the 0x prefix.');
    process.exit(1);
  }

  // Parse tags from command-line arguments (format: KEY=VALUE)
  const tags: Array<{ TagKey: string; TagValue: string }> = [];
  
  // Parse tags from environment variable (JSON format)
  if (process.env.KMS_TAGS) {
    try {
      const envTags = JSON.parse(process.env.KMS_TAGS);
      if (Array.isArray(envTags)) {
        tags.push(...envTags);
      }
    } catch (error) {
      console.warn('Warning: Invalid KMS_TAGS format. Expected JSON array. Ignoring.');
    }
  }
  
  // Parse tags from command-line arguments (format: KEY=VALUE)
  for (let i = 4; i < process.argv.length; i++) {
    const arg = process.argv[i];
    const match = arg.match(/^([^=]+)=(.*)$/);
    if (match) {
      tags.push({ TagKey: match[1], TagValue: match[2] });
    }
  }

  console.log('=== Import Ethereum Private Key to AWS KMS ===\n');
  console.log(`Region: ${region}`);
  console.log(`Alias: ${aliasName}`);
  if (tags.length > 0) {
    console.log(`Tags: ${tags.map(t => `${t.TagKey}=${t.TagValue}`).join(', ')}`);
  }
  console.log('');

  try {
    // Show a warning about security
    console.log('⚠️  Security Warning:');
    console.log('   - Your private key will be encrypted and imported into AWS KMS');
    console.log('   - The key material will be stored securely in AWS KMS HSM');
    console.log('   - After import, you can delete the original private key from your system\n');

    console.log('importKMSKey tags', tags);
    const result = await importKMSKey(
      privateKeyHex, 
      aliasName, 
      region, 
      undefined, // expirationDate
      tags.length > 0 ? tags : undefined
    );
    
    console.log('✓ Private key imported successfully!');
    console.log('  Key ID:', result.keyId);
    console.log('  ARN:', result.keyArn);
    if (result.aliasName.startsWith('alias/')) {
      console.log('  Alias:', result.aliasName);
    } else {
      console.log('  Note: No alias created (using key ID directly)');
    }
    
    // Get and display the Ethereum address
    try {
      const address = await getEthereumAddress(result.keyId, region);
      console.log('  Ethereum Address:', address);
    } catch (error: any) {
      console.warn('  Warning: Could not retrieve Ethereum address:', error.message);
    }
    
    console.log('\n✅ Key Import Complete!');
    console.log('   Your private key is now stored securely in AWS KMS');
    console.log('   You can now use this key to sign Ethereum transactions\n');
    console.log('Next steps:');
    console.log('1. Update your .env file with:');
    console.log(`   KMS_KEY_ID=${result.keyId}`);
    console.log(`   KMS_KEY_ARN=${result.keyArn}`);
    console.log('2. Run: npm run sign');
    console.log('\n⚠️  Remember to securely delete the original private key from your system!');
  } catch (error: any) {
    console.error('\nImport failed:', error.message);
    if (error.message.includes('Invalid private key')) {
      console.error('\nMake sure your private key is:');
      console.error('  - 64 hexadecimal characters (32 bytes)');
      console.error('  - Valid hex format (0-9, a-f, A-F)');
    }
    process.exit(1);
  }
}

main();

