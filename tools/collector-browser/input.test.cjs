const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { readInput } = require('./input.cjs');

function fixture(run) {
  const previous = process.cwd();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fh-browser-input-'));
  try {
    process.chdir(root);
    run();
  } finally {
    process.chdir(previous);
    fs.rmSync(root, {recursive: true});
  }
}

test('reads only the fixed private filename, not a command-line path', () => fixture(() => {
  fs.writeFileSync('browser.json', '{"source":"private"}', {mode: 0o600});
  fs.writeFileSync('outside.json', '{"source":"outside"}', {mode: 0o600});
  const previous = process.argv;
  try {
    process.argv = ['node', 'check.cjs', path.resolve('outside.json')];
    assert.deepEqual(readInput(), {source: 'private'});
  } finally {
    process.argv = previous;
  }
}));

test('rejects missing input', () => fixture(() => assert.throws(readInput)));
test('rejects symlinks without changing their target', () => fixture(() => {
  fs.writeFileSync('outside.json', '{}', {mode: 0o640});
  fs.chmodSync('outside.json', 0o640);
  fs.symlinkSync('outside.json', 'browser.json');
  assert.throws(readInput);
  assert.equal(fs.readFileSync('outside.json', 'utf8'), '{}');
  assert.equal(fs.statSync('outside.json').mode & 0o777, 0o640);
}));
test('rejects hard links', () => fixture(() => {
  fs.writeFileSync('outside.json', '{}', {mode: 0o600});
  fs.linkSync('outside.json', 'browser.json');
  assert.throws(readInput, /private owned regular file/);
}));
test('rejects directories', () => fixture(() => {
  fs.mkdirSync('browser.json', {mode: 0o700});
  assert.throws(readInput, /private owned regular file/);
}));
test('rejects public input permissions', () => fixture(() => {
  fs.writeFileSync('browser.json', '{}', {mode: 0o600});
  fs.chmodSync('browser.json', 0o644);
  assert.throws(readInput, /private owned regular file/);
}));
test('bounds input before JSON parsing', () => fixture(() => {
  fs.writeFileSync('browser.json', ' '.repeat(65537), {mode: 0o600});
  assert.throws(readInput, /size limit/);
}));
test('rejects malformed JSON and closes the descriptor', () => fixture(() => {
  fs.writeFileSync('browser.json', '{', {mode: 0o600});
  const close = fs.closeSync;
  const closed = [];
  fs.closeSync = fd => { closed.push(fd); return close(fd); };
  try {
    assert.throws(readInput, SyntaxError);
  } finally {
    fs.closeSync = close;
  }
  assert.equal(closed.length, 1);
  assert.throws(() => fs.fstatSync(closed[0]), {code: 'EBADF'});
  fs.writeFileSync('browser.json', '{}');
  assert.deepEqual(readInput(), {});
}));
