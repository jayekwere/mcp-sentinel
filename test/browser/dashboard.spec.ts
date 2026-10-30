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
