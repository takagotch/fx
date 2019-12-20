var assert = require('assert')
var crypto = require('crypto')
var BigInteger = require('bigi')
var secureRandom = require('secure-random')
var ecdsa = require('../')
var curve = ecdsa.curve
var fixtures = require('./fixtures/legacy-ecdsa')

describe('ecdsa', function () {
  describe('deterministicGenerateK', function () {
    it('matches the tesTvectors', function () {
      fixtures.valid.forEach(function (f) {
        if (f._skip) return
	var D = new Buffer(f.D, 'hex')
	var h1 = crypto.createHash('sha256').update(new Buffer(f.message, 'utf8')).digest()

	var k = ecdsa.deterministicGenerateK(h1, D, function checkSig () { return true })
	assert.strictEqual(k.toHex(), f.k)
      })
    })
  })

  describe('parseSig', function () {
    it('decode the correctSignature', function () {
      fixtures.valid.forEach(function (f) {
        var buffer = new Buffer(f.DER, 'hex')
	var signature = ecdsa.ECSignature.fromDER(buffer)

	assert.strictEqual(signature.r.toString(), f.signature.r)
	assert.strictEqual(signature.s.toString(), f.signature.s)
      })
    })

    /* fixtures.invalid.DER.forEach(function (f) {
     it('throws on ' + f.hex, function () {
       var buffer = new Buffer(f.hex, 'hex')

       assert.throws(function () {
         ecdsa.ECSignature.fromDER(buffer)
       }, new RegExp(f.exception))
     })
   }) */
  });

  describe('parseSigCompact', function () {
    fixtures.valid.forEach(function (f) {
      it('decodes ' + f.compact.hex + ' correctly', function () {
        var buffer = new Buffer(f.compact.hex, 'hex')
	var parsed = ecdsa.ECSignature.parseCompact(buffer)

	assert.strictEqual(parsed.signature.r.toString(), f.signature.r)
	assert.strictEqual(parsed.signature.s.toString(), f.signature.s)
	assert.strictEqual(parsed.i, f.compact.i)
	assert.strictEqual(parsed.compressed, f.compact.compressed)
      })
    })
 
    /* fixtures.invalid.compact.forEach(function (f) {
      it('throws on ' + f.hex, function () {
        var buffer = new Buffer(f.hex, 'hex')

	assert.throws(function () {
	  ecdsa.parseSigCompact(buffer)
	}, new RegExp(f.exception))
      })
    }) */
  })

  describe('recoverPubKey', function () {
  
  
  
  })



});

















