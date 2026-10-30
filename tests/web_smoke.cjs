// Optionele browserregressies; geen runtime-afhankelijkheid van de webapp.
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs/promises');
const {chromium} = require('playwright');

async function startDemo(token = '') {
  const child = spawn(process.env.PYTHON || 'python3', ['webwatch.py', '--demo', '--port', '0'], {
    cwd: path.resolve(__dirname, '..'), env: {...process.env, NETWORKWATCH_WEB_TOKEN: token}, stdio: ['ignore','pipe','pipe']
  });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  const url = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Demo startte niet: ' + stderr)), 10000);
    child.once('error', reject);
    child.once('exit', code => { clearTimeout(timeout); reject(new Error('Demo stopte: ' + code + ' ' + stderr)); });
    child.stdout.on('data', chunk => {
      const match = chunk.toString().match(/http:\/\/127\.0\.0\.1:\d+/);
      if (match) { clearTimeout(timeout); resolve(match[0]); }
    });
  });
  return {child, url, stop: () => child.kill('SIGTERM')};
}

(async () => {
  const demo = await startDemo();
  let browser, secure;
  try {
    const options = {headless: true};
    if (process.env.CHROMIUM_PATH) options.executablePath = process.env.CHROMIUM_PATH;
    browser = await chromium.launch(options);
    const context = await browser.newContext({viewport: {width: 1440, height: 1000}, locale: 'nl-NL'});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await page.goto(demo.url);
    await page.locator('#hosts-body tr').nth(3).waitFor();
    assert.equal(await page.locator('#total-count').textContent(), '4');
    assert.equal(await page.locator('#hosts-body tr').count(), 4);
    await fs.mkdir(path.resolve(__dirname, '../test-artifacts'), {recursive:true});
    await page.screenshot({path:'test-artifacts/networkwatch-desktop.png', fullPage:true});

    // Zoek/filter en direct herkennen.
    await page.locator('#search').fill('telefoon');
    await page.waitForFunction(() => document.querySelectorAll('#hosts-body tr').length === 1);
    await page.locator('#hosts-body input[type=checkbox]').check();
    await page.waitForFunction(() => document.querySelector('#unknown-count').textContent === '1');
    await page.locator('#search').fill('');
    await page.locator('#filter').selectOption('unknown');
    await page.waitForFunction(() => document.querySelectorAll('#hosts-body tr').length === 1);
    await page.locator('#filter').selectOption('all');
    await page.waitForFunction(() => document.querySelectorAll('#hosts-body tr').length === 4);

    // Apparaat bewerken via rechtsklik: Annuleren, Escape en bewaren.
    let row = page.locator('#hosts-body tr').filter({hasText:'Router'});
    await row.click({button:'right'});
    await page.locator('#host-menu').getByText('Apparaat bewerken', {exact:true}).click();
    await page.locator('#edit-label').fill('NIET OPSLAAN');
    await page.locator('#edit-dialog').getByRole('button', {name:'Annuleren (Esc)', exact:true}).click();
    assert.equal(await page.locator('#hosts-body').getByText('NIET OPSLAAN', {exact:true}).count(), 0);
    await row.dblclick();
    assert.equal(await page.locator('#edit-label').inputValue(), 'Router');
    await page.locator('#edit-label').fill('OOK NIET OPSLAAN');
    await page.keyboard.press('Escape');
    await row.dblclick();
    assert.equal(await page.locator('#edit-label').inputValue(), 'Router');
    await page.locator('#edit-label').fill('Browser-router');
    await page.locator('#edit-save').click();
    await page.locator('#hosts-body').getByText('Browser-router', {exact:true}).waitFor();

    // Poortdetails en een SSH-commando; geen client of echte host starten.
    row = page.locator('#hosts-body tr').filter({hasText:'Browser-router'});
    await row.click({button:'right'});
    await page.locator('#host-menu').getByText('Poortdetails', {exact:true}).click();
    assert.equal(await page.locator('#ports-body tr').count(), 3);
    await page.locator('#ports-dialog').getByRole('button', {name:'Sluiten', exact:true}).last().click();
    await row.click({button:'right'});
    await page.locator('#host-menu').getByText('SSH-sessie starten (22)', {exact:true}).click();
    await page.locator('#action-user').fill('jan');
    assert.equal(await page.locator('#action-command').inputValue(), "ssh -p 22 -l 'jan' 192.0.2.1");
    assert.equal(await page.locator('#launch-action').isDisabled(), true);
    await page.keyboard.press('Escape');

    // Alle instellingen-tabs, geldige JSON, demo-POST en annuleren van settings.
    await page.locator('#settings-button').click();
    await page.locator('#settings-dialog').waitFor();
    for (const name of ['ports','os','unknown','offline','network']) {
      await page.locator('#tab-' + name).click();
      assert.equal(await page.locator('#settings-' + name).isVisible(), true);
    }
    await page.locator('#cfg-profile').fill('NIET BEWAREN');
    await page.locator('#settings-dialog').getByRole('button', {name:'Annuleren (Esc)', exact:true}).click();
    await page.locator('#settings-button').click();
    await page.locator('#settings-dialog').waitFor();
    assert.equal(await page.locator('#cfg-profile').inputValue(), 'Voorbeeldnetwerk');
    await page.locator('#tab-unknown').click();
    await page.locator('#unknown-url').fill('https://example.invalid/test');
    await page.locator('#unknown-test').click();
    await page.locator('#unknown-test-result').getByText('Demo: geen POST verstuurd.', {exact:true}).waitFor();
    await page.locator('#tab-network').click();
    await page.locator('#cfg-profile').fill('Webtest');
    await page.locator('#settings-save').click();
    await page.waitForFunction(() => document.querySelector('#network-label').textContent.includes('Webtest'));
    await page.locator('#paused').check();
    await page.waitForFunction(() => document.querySelector('#scan-state').textContent.includes('gepauzeerd'));
    await page.locator('#scan-button').click();
    await page.waitForFunction(() => document.querySelectorAll('#hosts-body tr').length === 4);
    await page.getByRole('button', {name:'Gebeurtenissen', exact:true}).click();
    assert.ok(await page.locator('#events-body tr').count() >= 4);
    await page.getByRole('button', {name:/Apparaten/}).first().click();
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#export-link').click();
    const download = await downloadPromise;
    assert.equal(download.suggestedFilename(), 'networkwatch-apparaten.csv');

    // Smal scherm: navigatie, inhoud en vaste dialoogknoppen blijven bereikbaar.
    await page.setViewportSize({width:390,height:844});
    await page.locator('#settings-button').click();
    const cancel = page.locator('#settings-dialog').getByRole('button', {name:'Annuleren (Esc)', exact:true});
    const box = await cancel.boundingBox();
    assert.ok(box && box.y >= 0 && box.y + box.height <= 844);
    await page.locator('#tab-offline').click();
    const mobileLayout = await page.evaluate(() => ({viewport: innerWidth, root: document.documentElement.scrollWidth,
      body: document.body.getBoundingClientRect().width,
      wide: [...document.querySelectorAll('body *')].filter(e => e.getClientRects().length && e.getBoundingClientRect().right > innerWidth + 1).slice(0, 24).map(e => ({tag:e.tagName,id:e.id,cls:e.className,w:e.getBoundingClientRect().width,right:e.getBoundingClientRect().right,overflow:getComputedStyle(e).overflowX}))}));
    assert.ok(mobileLayout.root <= mobileLayout.viewport + 1, 'Mobiele layout: ' + JSON.stringify(mobileLayout));
    await page.screenshot({path:'test-artifacts/networkwatch-mobile.png', fullPage:true});
    await cancel.click();

    // Netwerkdata wordt tekst, ook als een hostnaam HTML bevat.
    await page.setViewportSize({width:1440,height:1000});
    await page.locator('#hosts-body tr').first().dblclick();
    await page.locator('#edit-label').fill('<img src=x onerror="window.bad=true">');
    await page.locator('#edit-save').click();
    await page.locator('#hosts-body').getByText('<img src=x onerror="window.bad=true">', {exact:true}).waitFor();
    assert.equal(await page.locator('#hosts-body img').count(), 0);
    assert.equal(await page.evaluate(() => Boolean(window.bad)), false);
    assert.deepEqual(errors, []);

    // Toegangscode bij een beveiligde server en sessiecookie na herladen.
    const token = 'networkwatch-browser-test-token-0123456789';
    secure = await startDemo(token);
    await page.goto(secure.url);
    await page.locator('#login-screen').waitFor();
    await page.locator('#login-token').fill(token);
    await page.locator('#login-form button').click();
    await page.locator('#hosts-body tr').nth(3).waitFor();
    await page.reload();
    await page.locator('#hosts-body tr').nth(3).waitFor();
    await page.locator('#logout-button').click();
    await page.locator('#login-screen').waitFor();
    assert.deepEqual(errors, []);
    console.log('Webbrowsercontroles geslaagd: overzicht, herkennen, bewerken, annuleren, Escape, poorten, acties, instellingen, demo-POST, scan, pauze, export, mobiel, veilige tekst en aanmelding.');
  } finally {
    if (browser) await browser.close();
    demo.stop(); if (secure) secure.stop();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
