#!/usr/bin/env node
// Generates identity/identity-map.json from identity/users.yaml.
//   node scripts/identity-build-map.js          write the file
//   node scripts/identity-build-map.js --check  exit 1 if the file is missing or stale (used by test-all.sh)

const fs = require('fs');
const { loadUsersYaml, validate, buildMap, MAP_JSON } = require('../identity/lib/directory');

const doc = loadUsersYaml();
const errors = validate(doc);
if (errors.length > 0) {
  console.error('identity/users.yaml is invalid:');
  errors.forEach(e => console.error(`  - ${e}`));
  process.exit(1);
}

const rendered = JSON.stringify(buildMap(doc), null, 2) + '\n';

if (process.argv.includes('--check')) {
  const current = fs.existsSync(MAP_JSON) ? fs.readFileSync(MAP_JSON, 'utf8') : null;
  if (current !== rendered) {
    console.error('identity/identity-map.json is out of date. Run: node scripts/identity-build-map.js');
    process.exit(1);
  }
  console.log('identity/identity-map.json is up to date.');
} else {
  fs.writeFileSync(MAP_JSON, rendered);
  console.log(`Wrote ${MAP_JSON} (${doc.users.length} users, ${doc.groups.length} groups).`);
}
