/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { expect } from 'chai'

describe('Sanity Tests', () => {
  describe('Basic JavaScript Operations', () => {
    it('should perform basic arithmetic correctly', () => {
      const result = 2 + 2
      expect(result).to.equal(4)
    })

    it('should handle string concatenation', () => {
      const greeting = 'Hello' + ' ' + 'World'
      expect(greeting).to.equal('Hello World')
    })

    it('should work with arrays', () => {
      const numbers = [1, 2, 3, 4, 5]
      expect(numbers).to.have.lengthOf(5)
      expect(numbers[0]).to.equal(1)
      expect(numbers[4]).to.equal(5)
    })
  })

  describe('Environment Checks', () => {
    it('should have Node.js environment available', () => {
      expect(process).to.exist
      expect(process.version).to.be.a('string')
    })

    it('should have access to global objects', () => {
      expect(global).to.exist
      expect(Object).to.exist
      expect(Array).to.exist
    })
  })

  describe('Async Operations', () => {
    it('should handle promises correctly', async () => {
      const promise = Promise.resolve('success')
      const result = await promise
      expect(result).to.equal('success')
    })

    it('should handle setTimeout correctly', (done) => {
      setTimeout(() => {
        expect(true).to.be.true
        done()
      }, 10)
    })
  })
})
