/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { retrieveChallengesWithCodeSnippet } from '../../routes/vulnCodeSnippet'
import { readFixes } from '../../routes/vulnCodeFixes'
import fs from 'graceful-fs'

void describe('codingChallengeFixes', () => {
  let codingChallenges: string[]
  before(async () => {
    codingChallenges = await retrieveChallengesWithCodeSnippet()
  })

  void it('should have a correct fix for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      const fixes = readFixes(challenge)
      assert.ok(fixes.correct > -1, `Coding challenge ${challenge} does not have a correct fix file`)
    }
  })

  void it('should have a total of three or more fix options for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      const fixes = readFixes(challenge)
      assert.ok(fixes.fixes.length >= 3, `Coding challenge ${challenge} does not have enough fix option files`)
    }
  })

  void it('should have an info YAML file for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      assert.equal(fs.existsSync('./data/static/codefixes/' + challenge + '.info.yml'), true, `Coding challenge ${challenge} does not have an info YAML file`)
    }
  })
})

void describe('web3WalletChallenge code fixes', () => {
  // Tests validating that the web3WalletChallenge fix files are correctly structured
  // and that the incorrect fix #4 (CWE-863 Incorrect Authorization / reentrancy) is
  // properly flagged as wrong while the correct fix #3 is identified as secure.

  void it('should load exactly 4 fix options for web3WalletChallenge', () => {
    const fixes = readFixes('web3WalletChallenge')
    assert.equal(fixes.fixes.length, 4, 'web3WalletChallenge should have exactly 4 fix options')
  })

  void it('should identify fix #3 (0-indexed: 2) as the correct fix for web3WalletChallenge', () => {
    const fixes = readFixes('web3WalletChallenge')
    // _3_correct.sol is the correct fix: correct = parseInt("3") - 1 = 2
    assert.equal(fixes.correct, 2, 'Fix #3 (0-indexed: 2) should be the correct fix for web3WalletChallenge')
  })

  void it('should confirm the correct fix uses Checks-Effects-Interactions pattern (balance decremented before external call)', () => {
    const fixes = readFixes('web3WalletChallenge')
    const correctFix = fixes.fixes[fixes.correct]
    // The secure fix must deduct balance BEFORE the external call to prevent reentrancy
    const balanceDeductionIndex = correctFix.indexOf('balances[msg.sender] -= _amount')
    const externalCallIndex = correctFix.indexOf('msg.sender.call')
    assert.ok(balanceDeductionIndex !== -1, 'Correct fix must deduct the balance')
    assert.ok(externalCallIndex !== -1, 'Correct fix must make the external call')
    assert.ok(
      balanceDeductionIndex < externalCallIndex,
      'Correct fix must deduct balance BEFORE the external call (Checks-Effects-Interactions)'
    )
  })

  void it('should confirm the correct fix uses proper balance check (>= not <=)', () => {
    const fixes = readFixes('web3WalletChallenge')
    const correctFix = fixes.fixes[fixes.correct]
    // Proper authorization check: sender must have sufficient balance
    assert.ok(
      correctFix.includes('balances[msg.sender] >= _amount'),
      'Correct fix must check that balance is greater than or equal to amount (not <=)'
    )
  })

  void it('should confirm fix #4 is not identified as the correct solution (it is a distractor)', () => {
    const fixes = readFixes('web3WalletChallenge')
    // Fix #4 is a distractor option (0-indexed: 3) — it is NOT the correct answer
    // The correct answer is fix #3 (0-indexed: 2)
    assert.notEqual(fixes.correct, 3, 'Fix #4 (0-indexed: 3) must not be identified as the correct fix')
  })

  void it('should confirm the incorrect fix #4 does not have a backwards balance check', () => {
    // After remediation, fix #4 should no longer have the backwards `<= _amount` check
    // which allowed unauthorized withdrawals regardless of balance
    const fixes = readFixes('web3WalletChallenge')
    const fix4 = fixes.fixes[3]
    assert.ok(
      !fix4.includes('balances[msg.sender] <= _amount'),
      'Remediated fix #4 must not use the backwards balance check (<=) that enables unauthorized withdrawal'
    )
  })

  void it('should confirm the incorrect fix #4 does not increase balance on withdrawal', () => {
    // After remediation, fix #4 must not use += (adding to balance) after withdrawal
    const fixes = readFixes('web3WalletChallenge')
    const fix4 = fixes.fixes[3]
    // The vulnerability had `balances[msg.sender] += _amount` — adding instead of subtracting
    assert.ok(
      !fix4.includes('balances[msg.sender] += _amount'),
      'Remediated fix #4 must not increase the sender balance after a withdrawal'
    )
  })

  void it('should confirm all fix files for web3WalletChallenge are non-empty Solidity contracts', () => {
    const fixes = readFixes('web3WalletChallenge')
    for (const fix of fixes.fixes) {
      assert.ok(fix.length > 0, 'Each fix file must be non-empty')
      assert.ok(
        fix.includes('pragma solidity') || fix.includes('contract '),
        'Each fix file must contain Solidity contract code'
      )
    }
  })
})
