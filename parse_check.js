const fs = require('fs');
const path = require('path');
const file = path.join(__dirname, 'index.html');
const html = fs.readFileSync(file, 'utf8');
const start = html.indexOf('<script>');
const end = html.indexOf('</script>', start);
if (start === -1 || end === -1) {
  console.error('Script tag not found');
  process.exit(2);
}
const script = html.slice(start + '<script>'.length, end);
try {
  new Function(script);
  console.log('OK: No syntax errors detected (function compilation succeeded).');
} catch (e) {
  console.error('SYNTAX ERROR during compilation:');
  console.error(e.stack || e.toString());
  process.exit(1);
}
