#!/usr/bin/env node

/**
 * CLI: List all KMS keys
 */

import { listKMSKeys, KeyInfo } from '../core/list';

function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength - 3) + '...';
}

function formatTable(keys: KeyInfo[], includeDetails: boolean): void {
  if (keys.length === 0) {
    console.log('No KMS keys found in this region.');
    return;
  }

  if (!includeDetails) {
    // Simple table format
    console.log('┌─────────────────────────────────────────────────────────────────────────────┐');
    console.log('│ Key ID                                                          │ Alias      │');
    console.log('├─────────────────────────────────────────────────────────────────────────────┤');
    
    keys.forEach((key) => {
      const keyId = truncate(key.keyId, 60);
      const alias = key.alias ? truncate(key.alias.replace('alias/', ''), 10) : '-';
      console.log(`│ ${keyId.padEnd(60)} │ ${alias.padEnd(10)} │`);
    });
    
    console.log('└─────────────────────────────────────────────────────────────────────────────┘');
    return;
  }

  // Detailed table format
  const rows: string[][] = [];
  
  keys.forEach((key) => {
    const keyId = truncate(key.keyId, 30);
    const alias = key.alias ? truncate(key.alias.replace('alias/', ''), 20) : '-';
    const keySpec = key.keySpec || '-';
    const keySpecDisplay = keySpec === 'ECC_SECG_P256K1' ? '✓ secp256k1' : keySpec;
    const state = key.enabled ? '✓ Enabled' : '✗ Disabled';
    const created = key.creationDate 
      ? key.creationDate.toISOString().split('T')[0] 
      : '-';
    const description = key.description ? truncate(key.description, 30) : '-';
    
    // Format tags as "Key1:Value1, Key2:Value2"
    let tagsDisplay = '-';
    if (key.tags && Object.keys(key.tags).length > 0) {
      const tagPairs = Object.entries(key.tags)
        .map(([k, v]) => `${k}:${v}`)
        .join(', ');
      tagsDisplay = truncate(tagPairs, 40);
    }
    
    rows.push([keyId, alias, keySpecDisplay, state, created, description, tagsDisplay]);
  });

  // Calculate column widths
  const headers = ['Key ID', 'Alias', 'Key Spec', 'State', 'Created', 'Description', 'Tags'];
  const colWidths = headers.map((header, i) => {
    const maxContentWidth = Math.max(
      header.length,
      ...rows.map(row => row[i].length)
    );
    return Math.min(maxContentWidth + 2, 
      i === 0 ? 32 : 
      i === 1 ? 22 : 
      i === 2 ? 15 : 
      i === 3 ? 12 : 
      i === 4 ? 12 : 
      i === 5 ? 32 : 
      42); // Tags column
  });

  // Print table header
  const topBorder = '┌' + colWidths.map(w => '─'.repeat(w)).join('┬') + '┐';
  const headerRow = '│' + headers.map((h, i) => ` ${h.padEnd(colWidths[i] - 1)}`).join('│') + '│';
  const separator = '├' + colWidths.map(w => '─'.repeat(w)).join('┼') + '┤';
  const bottomBorder = '└' + colWidths.map(w => '─'.repeat(w)).join('┴') + '┘';

  console.log(topBorder);
  console.log(headerRow);
  console.log(separator);

  // Print data rows
  rows.forEach((row) => {
    const rowStr = '│' + row.map((cell, i) => ` ${cell.padEnd(colWidths[i] - 1)}`).join('│') + '│';
    console.log(rowStr);
  });

  console.log(bottomBorder);
}

async function main() {
  const region = process.env.AWS_REGION || 'us-east-1';
  
  // Parse command line arguments
  // Note: When using npm run, use -- separator: npm run list -- --tag KEY=VALUE
  // Or use direct format: npm run list -- KEY=VALUE
  let includeDetails = true;
  let tagFilter: { key: string; value: string } | undefined;
  
  // Debug: log received arguments
  if (process.env.DEBUG) {
    console.log('DEBUG: process.argv =', process.argv);
  }
  
  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    
    if (arg === '--simple') {
      includeDetails = false;
    } else if (arg === '--tag' && i + 1 < process.argv.length) {
      // Format: --tag KEY=VALUE
      const tagArg = process.argv[++i];
      const match = tagArg.match(/^([^=]+)=(.*)$/);
      if (match) {
        tagFilter = { key: match[1], value: match[2] };
      } else {
        console.error(`Error: Invalid tag format. Expected KEY=VALUE, got: ${tagArg}`);
        console.error('Usage: npm run list -- [--simple] [--tag KEY=VALUE]');
        console.error('   or: npm run list -- KEY=VALUE');
        process.exit(1);
      }
    } else if (arg.includes('=') && arg.indexOf('=') > 0) {
      // Format: KEY=VALUE (positional argument)
      // This handles: npm run list -- KEY=VALUE
      // Note: npm may consume --tag flag, so KEY=VALUE might come through directly
      const match = arg.match(/^([^=]+)=(.*)$/);
      if (match) {
        // Only set if not already set (to avoid overriding --tag format)
        if (!tagFilter) {
          tagFilter = { key: match[1], value: match[2] };
        }
      }
    } else if (arg === '--help' || arg === '-h') {
      console.log('Usage: npm run list [OPTIONS]');
      console.log('');
      console.log('Options:');
      console.log('  --simple              Show simplified table (no details)');
      console.log('  --tag KEY=VALUE       Filter keys by tag (e.g., --tag Purpose=EthereumSigning)');
      console.log('  KEY=VALUE             Alternative format for tag filter');
      console.log('  --help, -h            Show this help message');
      console.log('');
      console.log('Examples:');
      console.log('  npm run list');
      console.log('  npm run list --simple');
      console.log('  npm run list -- --tag Purpose=EthereumSigning');
      console.log('  npm run list -- Purpose=EthereumSigning');
      console.log('');
      console.log('Note: When using npm run, use -- separator before flags:');
      console.log('  npm run list -- --tag KEY=VALUE');
      process.exit(0);
    }
  }
  
  console.log('=== AWS KMS Keys ===\n');
  console.log(`Region: ${region}`);
  if (tagFilter) {
    console.log(`Filter: Tag ${tagFilter.key} = ${tagFilter.value}\n`);
  } else {
    console.log('');
  }

  try {
    const keys = await listKMSKeys(region, includeDetails, tagFilter);
    
    if (tagFilter && keys.length === 0) {
      console.log(`No KMS keys found matching tag filter: ${tagFilter.key}=${tagFilter.value}`);
      return;
    }
    
    formatTable(keys, includeDetails);

    // Summary
    if (includeDetails && keys.length > 0) {
      const ethereumKeys = keys.filter(k => k.keySpec === 'ECC_SECG_P256K1');
      const enabledKeys = keys.filter(k => k.enabled);
      const keysWithTags = keys.filter(k => k.tags && Object.keys(k.tags).length > 0);
      
      console.log('\nSummary:');
      console.log(`  Total keys: ${keys.length}`);
      console.log(`  Ethereum-compatible (secp256k1): ${ethereumKeys.length}`);
      console.log(`  Enabled: ${enabledKeys.length}`);
      console.log(`  Disabled: ${keys.length - enabledKeys.length}`);
      console.log(`  Keys with tags: ${keysWithTags.length}`);

      // Display detailed tags section
      if (keysWithTags.length > 0) {
        console.log('\nTags Details:');
        keysWithTags.forEach((key) => {
          const keyIdentifier = key.alias ? key.alias.replace('alias/', '') : key.keyId;
          console.log(`  ${keyIdentifier}:`);
          if (key.tags) {
            Object.entries(key.tags).forEach(([tagKey, tagValue]) => {
              console.log(`    ${tagKey}: ${tagValue}`);
            });
          }
        });
      }
    }
  } catch (error: any) {
    console.error('\n❌ Error:', error.message || error);
    if (error.stack && process.env.DEBUG) {
      console.error('\nStack trace:', error.stack);
    }
    process.exit(1);
  }
}

main();

