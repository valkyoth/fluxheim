// The caller selects an unmounted private working directory, not an input path.
const fs = require('node:fs');
const LIMIT = 64 * 1024;

function readInput() {
  const fd = fs.openSync('browser.json', fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.nlink !== 1 || info.uid !== process.getuid() || (info.mode & 0o077) !== 0) {
      throw new Error('browser input must be a private owned regular file');
    }
    const bytes = Buffer.alloc(LIMIT + 1);
    let count = 0;
    while (count < bytes.length) {
      const read = fs.readSync(fd, bytes, count, bytes.length - count, null);
      if (read === 0) break;
      count += read;
    }
    if (count > LIMIT) throw new Error('browser input exceeds size limit');
    return JSON.parse(bytes.toString('utf8', 0, count));
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { readInput };
