// Credentials arrive in a private file, never argv or a committed dashboard.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { readInput } = require('./input.cjs');
assert.equal(require('playwright/package.json').version, require('./package.json').devDependencies.playwright);
let stage = 'browser startup';

async function plotted(page) {
  await page.locator('canvas').first().waitFor();
  await page.waitForFunction(() => [...document.querySelectorAll('canvas')].some(canvas => {
    const context = canvas.getContext('2d');
    if (!context || canvas.width < 100 || canvas.height < 100) return false;
    const data = context.getImageData(0, 0, canvas.width, canvas.height).data;
    let colored = 0;
    for (let i = 0; i < data.length; i += 4) {
      if (data[i + 3] && Math.max(data[i], data[i + 1], data[i + 2]) - Math.min(data[i], data[i + 1], data[i + 2]) > 40) colored++;
    }
    return colored > 30;
  }));
}

(async () => {
  assert.equal(process.argv.length, 2, 'browser driver does not accept input paths');
  const input = readInput();
  for (const port of [input.grafana, input.signoz, input.jaeger].filter(Boolean)) {
    assert(Number.isInteger(port) && port > 0 && port < 65536);
  }
  assert(/^[a-f0-9]{32}$/.test(input.trace));
  const browser = await chromium.launch({headless: true});
  let page;
  const queryRequests = [];
  try {
    const context = await browser.newContext({viewport: {width: 1440, height: 1000}});
    page = await context.newPage();
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.hostname === '127.0.0.1' && Number(url.port) === input.signoz &&
          url.pathname.endsWith('/query_range') && queryRequests.length < 4) {
        queryRequests.push({path: url.pathname, body: (request.postData() || '').slice(0, 16000)});
      }
    });
    stage = 'Grafana login';
    await page.goto(`http://127.0.0.1:${input.grafana}/login`);
    await page.getByLabel('Email or username').fill('fluxheim');
    await page.getByLabel('Password', {exact: true}).fill(input.password);
    await page.getByRole('button', {name: 'Log in', exact: true}).click();
    await page.waitForURL(url => !url.pathname.startsWith('/login'));
    stage = 'Grafana dashboard';
    await page.goto(`http://127.0.0.1:${input.grafana}/d/fluxheim-operations-v1?from=now-5m&to=now&var-job=fluxheim-scrape&var-instance=All`);
    await page.getByText('Requests / second', {exact: true}).waitFor();
    await plotted(page);
    await page.screenshot({path: path.join(input.output, 'grafana.png'), fullPage: true});
    stage = 'Jaeger event-to-trace link';
    await page.setContent(`<a href="http://127.0.0.1:${input.jaeger}/trace/${input.trace}">Trace from captured event</a>`);
    await page.getByRole('link', {name: 'Trace from captured event'}).click();
    await page.getByText('HTTP request', {exact: true}).first().waitFor();
    assert(page.url().includes(input.trace));
    await page.screenshot({path: path.join(input.output, 'jaeger-trace.png'), fullPage: true});
    if (input.signoz) {
      stage = 'SigNoz login';
      await page.goto(`http://127.0.0.1:${input.signoz}/login`);
      await page.getByTestId('email').fill('fluxheim@example.test');
      await page.getByRole('button', {name: 'Next', exact: true}).click();
      await page.getByTestId('password').fill(input.password);
      await page.getByRole('button', {name: 'Sign in with Password', exact: true}).click();
      await page.waitForURL(url => !url.pathname.startsWith('/login'));
      stage = 'SigNoz dashboard';
      await page.goto(`http://127.0.0.1:${input.signoz}/dashboard/${input.dashboard}?relativeTime=5m`);
      await page.getByText('Requests / second', {exact: true}).waitFor();
      await plotted(page);
      await page.screenshot({path: path.join(input.output, 'signoz.png'), fullPage: true});
      stage = 'SigNoz event-to-trace link';
      await page.setContent(`<a href="http://127.0.0.1:${input.signoz}/trace/${input.trace}">Trace from captured event</a>`);
      await page.getByRole('link', {name: 'Trace from captured event'}).click();
      await page.getByText('HTTP request', {exact: true}).first().waitFor();
      assert(page.url().includes(input.trace));
      await page.screenshot({path: path.join(input.output, 'signoz-trace.png'), fullPage: true});
    }
    await context.close();
    console.log('Imported dashboard browser rendering: passed');
  } catch (error) {
    if (page && stage.endsWith('dashboard')) {
      await page.screenshot({path: path.join(input.output, 'render-failure.private.png'), fullPage: true});
      fs.writeFileSync(path.join(input.output, 'render-failure.private.txt'),
        (await page.locator('body').innerText()).slice(0, 8000), {mode: 0o600});
      fs.writeFileSync(path.join(input.output, 'queries.private.json'), JSON.stringify(queryRequests), {mode: 0o600});
    }
    throw error;
  } finally {
    await browser.close();
  }
})().catch(() => { console.error(`Dashboard rendering failed at ${stage}; no credentials recorded`); process.exitCode = 1; });
