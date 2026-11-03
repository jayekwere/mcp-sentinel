import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
const tokens = () => JSON.parse(readFileSync('test-results/tokens.json', 'utf8'));
test('dashboard workflow, safe rendering, and mobile layout', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/');
  await page.getByLabel('Access token', { exact: true }).fill(tokens().operator);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#integrity')).toHaveText('Audit chain verified');
  await expect(page.locator('#suspension-list')).toContainText('demo-agent');
  await page.getByRole('button', { name: 'Lift suspension', exact: true }).click();
  await expect(page.locator('#suspension-list')).toHaveText('No active suspensions.');
  await page.getByLabel('Agent access token', { exact: true }).fill(tokens().agent);
  await page.locator('#tool').selectOption('evidence.export');
  await page.getByRole('button', { name: 'Request approval', exact: true }).click();
  await expect(page.locator('#output')).toContainText('pending');
  const approvalId = await page.locator('#approval-id').inputValue();
  await page
    .locator('.review-item')
    .filter({ hasText: approvalId })
    .getByRole('button', { name: 'Approve once' })
    .click();
  await expect(page.locator('#notice')).toContainText('Approval granted');
  await page.getByRole('button', { name: 'Execute request', exact: false }).click();
  await expect(page.locator('#output')).toContainText('allowed');
  await page.getByRole('button', { name: 'Execute request', exact: false }).click();
  await expect(page.locator('#output')).toHaveText('approval_required');
  await page.getByLabel('Access token', { exact: true }).fill('');
  await page.screenshot({ path: 'test-results/dashboard-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator('h1')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: 'test-results/dashboard-mobile.png', fullPage: true });
  expect(errors).toEqual([]);
});

test('custom approval shows bounded arguments and renders injected markup as text', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/');
  await page.getByLabel('Access token', { exact: true }).fill(tokens().operator);
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await page.getByLabel('Agent access token', { exact: true }).fill(tokens().agent);
  await page.locator('#tool').selectOption('cloud.audit.summary');
  const markup = '<img src=x onerror=alert(1)>';
  await page
    .locator('#arguments')
    .fill(
      JSON.stringify({ provider: 'aws', records: [{ eventID: markup, long: 'x'.repeat(5000) }] }),
    );
  await page.getByRole('button', { name: 'Request approval', exact: true }).click();
  const box = page.locator('.review-item').filter({ hasText: 'cloud.audit.summary' });
  await expect(box).toContainText(markup);
  await expect(box).toContainText('[truncated at 4 KB]');
  await expect(box.locator('img')).toHaveCount(0);
  expect(errors).toEqual([]);
});
