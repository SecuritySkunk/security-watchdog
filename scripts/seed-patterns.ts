#!/usr/bin/env tsx
/**
 * Security Watchdog — Seed Default PII Patterns
 * 
 * Populates the registry with common PII detection patterns.
 */

import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';

const DB_PATH = process.env['WATCHDOG_DB_PATH'] ?? 
  path.join(process.env['HOME'] ?? '~', '.openclaw', 'security', 'registry.db');

// Default locale
const DEFAULT_LOCALE = {
  locale_id: 'us',
  display_name: 'United States',
  description: 'US PII patterns including SSN, phone numbers, and financial data',
  is_active: 1,
  priority: 100,
};

// Default patterns
const DEFAULT_PATTERNS = [
  // Government IDs
  {
    category: 'government_id',
    pattern_type: 'ssn',
    display_name: 'US Social Security Number',
    regex_pattern: '\\b(?!000|666|9\\d{2})\\d{3}[-\\s]?(?!00)\\d{2}[-\\s]?(?!0000)\\d{4}\\b',
    regex_flags: '',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['123-45-6789', '123 45 6789', '123456789']),
  },
  {
    category: 'government_id',
    pattern_type: 'drivers_license',
    display_name: 'US Drivers License',
    regex_pattern: '\\b[A-Z]{1,2}\\d{5,8}\\b',
    regex_flags: 'i',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['A1234567', 'AB12345678']),
  },
  {
    category: 'government_id',
    pattern_type: 'passport',
    display_name: 'US Passport Number',
    regex_pattern: '\\b[A-Z]\\d{8}\\b',
    regex_flags: 'i',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['C12345678']),
  },

  // Financial
  {
    category: 'financial',
    pattern_type: 'credit_card',
    display_name: 'Credit Card Number',
    regex_pattern: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b',
    regex_flags: '',
    validation_function: 'luhnCheck',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['4111111111111111', '5500000000000004']),
  },
  {
    category: 'financial',
    pattern_type: 'bank_account',
    display_name: 'Bank Account Number',
    regex_pattern: '\\b\\d{8,17}\\b',
    regex_flags: '',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['12345678901']),
  },
  {
    category: 'financial',
    pattern_type: 'routing_number',
    display_name: 'US Bank Routing Number',
    regex_pattern: '\\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|8[0-8])\\d{7}\\b',
    regex_flags: '',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['021000021', '111000025']),
  },

  // Contact Information
  {
    category: 'contact',
    pattern_type: 'email',
    display_name: 'Email Address',
    regex_pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b',
    regex_flags: 'i',
    default_classification: 'ASK_FIRST',
    example_values: JSON.stringify(['user@example.com', 'john.doe@company.co.uk']),
  },
  {
    category: 'contact',
    pattern_type: 'phone_us',
    display_name: 'US Phone Number',
    regex_pattern: '\\b(?:\\+1[-\\s]?)?(?:\\(?\\d{3}\\)?[-\\s]?)?\\d{3}[-\\s]?\\d{4}\\b',
    regex_flags: '',
    default_classification: 'ASK_FIRST',
    example_values: JSON.stringify(['+1-555-123-4567', '(555) 123-4567', '555-123-4567']),
  },
  {
    category: 'contact',
    pattern_type: 'address_us',
    display_name: 'US Street Address',
    regex_pattern: '\\b\\d{1,5}\\s+[A-Za-z]+(?:\\s+[A-Za-z]+)*\\s+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Dr|Drive|Ln|Lane|Way|Ct|Court|Pl|Place)\\b',
    regex_flags: 'i',
    default_classification: 'ASK_FIRST',
    example_values: JSON.stringify(['123 Main Street', '456 Oak Ave']),
  },
  {
    category: 'contact',
    pattern_type: 'zipcode_us',
    display_name: 'US ZIP Code',
    regex_pattern: '\\b\\d{5}(?:-\\d{4})?\\b',
    regex_flags: '',
    default_classification: 'INTERNAL_ONLY',
    example_values: JSON.stringify(['12345', '12345-6789']),
  },

  // Health
  {
    category: 'health',
    pattern_type: 'medical_record',
    display_name: 'Medical Record Number',
    regex_pattern: '\\bMRN[-:\\s]?\\d{6,10}\\b',
    regex_flags: 'i',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['MRN: 1234567890', 'MRN-123456']),
  },

  // Technology
  {
    category: 'technology',
    pattern_type: 'api_key',
    display_name: 'API Key (Generic)',
    regex_pattern: '\\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)[\\s=:]+["\']?([A-Za-z0-9_-]{20,})["\'\\s]?',
    regex_flags: 'i',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['api_key=abc123xyz456def789ghi']),
  },
  {
    category: 'technology',
    pattern_type: 'aws_key',
    display_name: 'AWS Access Key',
    regex_pattern: '\\bAKIA[0-9A-Z]{16}\\b',
    regex_flags: '',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['AKIAIOSFODNN7EXAMPLE']),
  },
  {
    category: 'technology',
    pattern_type: 'private_key',
    display_name: 'Private Key (PEM)',
    regex_pattern: '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    regex_flags: '',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['-----BEGIN PRIVATE KEY-----']),
  },
  {
    category: 'technology',
    pattern_type: 'password',
    display_name: 'Password in Text',
    regex_pattern: '\\b(?:password|passwd|pwd)[\\s=:]+["\']?([^\\s"\']{6,})["\'\\s]?',
    regex_flags: 'i',
    default_classification: 'NEVER_SHARE',
    example_values: JSON.stringify(['password=mysecret123', "password: 'hunter2'"]),
  },
  {
    category: 'technology',
    pattern_type: 'ip_address',
    display_name: 'IP Address (v4)',
    regex_pattern: '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b',
    regex_flags: '',
    default_classification: 'INTERNAL_ONLY',
    example_values: JSON.stringify(['192.168.1.1', '10.0.0.1']),
  },

  // Personal
  {
    category: 'personal',
    pattern_type: 'date_of_birth',
    display_name: 'Date of Birth',
    regex_pattern: '\\b(?:DOB|birth\\s?date|born)[:\\s]+(?:\\d{1,2}[-/]\\d{1,2}[-/]\\d{2,4}|\\d{4}[-/]\\d{1,2}[-/]\\d{1,2})\\b',
    regex_flags: 'i',
    default_classification: 'ASK_FIRST',
    example_values: JSON.stringify(['DOB: 01/15/1990', 'birthdate: 1990-01-15']),
  },
];

async function main() {
  console.log('Security Watchdog — Pattern Seeder');
  console.log('===================================\n');

  if (!fs.existsSync(DB_PATH)) {
    console.error(`Error: Database not found at ${DB_PATH}`);
    console.error('Run "npm run db:init" first.');
    process.exit(1);
  }

  const db = new Database(DB_PATH);
  db.pragma('foreign_keys = ON');

  // Check if locale exists
  const existingLocale = db.prepare('SELECT locale_id FROM locales WHERE locale_id = ?')
    .get(DEFAULT_LOCALE.locale_id);

  if (!existingLocale) {
    console.log(`Creating locale: ${DEFAULT_LOCALE.display_name}`);
    db.prepare(`
      INSERT INTO locales (locale_id, display_name, description, is_active, priority)
      VALUES (@locale_id, @display_name, @description, @is_active, @priority)
    `).run(DEFAULT_LOCALE);
  } else {
    console.log(`Locale already exists: ${DEFAULT_LOCALE.locale_id}`);
  }

  // Insert patterns
  const insertPattern = db.prepare(`
    INSERT OR REPLACE INTO patterns (
      locale_id, category, pattern_type, display_name, 
      regex_pattern, regex_flags, validation_function,
      default_classification, example_values, is_active
    ) VALUES (
      @locale_id, @category, @pattern_type, @display_name,
      @regex_pattern, @regex_flags, @validation_function,
      @default_classification, @example_values, 1
    )
  `);

  let inserted = 0;
  let updated = 0;

  for (const pattern of DEFAULT_PATTERNS) {
    const existing = db.prepare(`
      SELECT id FROM patterns 
      WHERE locale_id = ? AND category = ? AND pattern_type = ?
    `).get(DEFAULT_LOCALE.locale_id, pattern.category, pattern.pattern_type);

    insertPattern.run({
      locale_id: DEFAULT_LOCALE.locale_id,
      ...pattern,
      validation_function: pattern.validation_function ?? null,
    });

    if (existing) {
      updated++;
    } else {
      inserted++;
    }
    console.log(`  ${existing ? '↻' : '+'} ${pattern.display_name} (${pattern.category}/${pattern.pattern_type})`);
  }

  console.log(`\n✓ Done: ${inserted} inserted, ${updated} updated`);

  // Show summary
  const stats = db.prepare(`
    SELECT category, COUNT(*) as count 
    FROM patterns 
    WHERE locale_id = ? AND is_active = 1
    GROUP BY category
  `).all(DEFAULT_LOCALE.locale_id) as { category: string; count: number }[];

  console.log('\nPattern Summary:');
  for (const row of stats) {
    console.log(`  ${row.category}: ${row.count} patterns`);
  }

  db.close();
}

main().catch(console.error);
