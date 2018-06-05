const sinon = require('sinon')
const chai = require('chai')
const rewire = require('rewire')
chai.should()
chai.use(require('chai-as-promised'))
const jwkToPem = require('jwk-to-pem')

describe('CognitoValidator', () => {
  let requestMock
  let jwtMock
  let decodedToken
  let validator

  beforeEach(() => {
    const CognitoValidator = rewire('./index')
    requestMock = sinon.mock(CognitoValidator.__get__('request'))
    jwtMock = sinon.mock(CognitoValidator.__get__('jwt'))
    validator = new CognitoValidator('us-west-2', 'USER_POOL_ID', 'CLIENT_ID')
    decodedToken = {
      header: {
        kid: 'kid',
        alg: 'RS256'
      },
      payload: {
        sub: 'uuid',
        iss: 'https://cognito-idp.us-west-2.amazonaws.com/USER_POOL_ID',
        phone_number_verified: true,
        'cognito:username': 'uuid',
        aud: 'CLIENT_SECRET',
        auth_time: 1527999477,
        phone_number: '+15555555555',
        exp: 1528003077,
        iat: 1527999477
      },
      signature: 'signature'
    }
  })

  afterEach(() => {
    jwtMock.restore()
    requestMock.restore()
  })

  it('should initialize correctly', () => {
    validator.getRegion().should.equal('us-west-2')
    validator.getUserPoolId().should.equal('USER_POOL_ID')
    validator.getClientId().should.equal('CLIENT_ID')
    validator.getKeysUrl()
      .should.equal('https://cognito-idp.us-west-2.amazonaws.com/USER_POOL_ID/.well-known/jwks.json')
  })

  describe('validate', () => {
    let body

    beforeEach(() => {
      body = {
        keys: [{
          alg: 'RS256',
          e: 'AQAB',
          kid: 'kid',
          kty: 'RSA',
          n: 'nvalue',
          use: 'sig'
        }, {
          alg: 'RS256',
          e: 'AQAB',
          kid: 'other',
          kty: 'RSA',
          n: 'nvalue',
          use: 'sig'
        }]
      }
    })

    it('should return an error if the token is not a jwtMock', () => {
      jwtMock.expects('decode').withExactArgs('token', { complete: true }).returns(null)
      return validator.validate('token')
        .should.be.rejectedWith('Object is not a JSON web token').then(() => {
          jwtMock.verify()
        })
    })

    it('should return an error if there is an error calling the public key endpoint', () => {
      jwtMock.expects('decode').withExactArgs('token', { complete: true }).returns(decodedToken)
      requestMock.expects('get')
        .withExactArgs(
          'https://cognito-idp.us-west-2.amazonaws.com/USER_POOL_ID/.well-known/jwks.json',
          sinon.match.func
        )
        .callsFake((url, cb) => {
          cb(new Error('error'), { statusCode: '500' })
        })
      return validator.validate('token')
        .should.be.rejectedWith('Unable to obtain keys: error').then(() => {
          jwtMock.verify()
          requestMock.verify()
        })
    })

    it('should return an error if keys are not included in the public key response', () => {
      body = {}
      jwtMock.expects('decode').withExactArgs('token', { complete: true }).returns(decodedToken)
      requestMock.expects('get')
        .withExactArgs(
          'https://cognito-idp.us-west-2.amazonaws.com/USER_POOL_ID/.well-known/jwks.json',
          sinon.match.func
        )
        .callsFake((url, cb) => {
          cb(null, { statusCode: '200' }, body)
        })
      return validator.validate('token')
        .should.be.rejectedWith('Response from endpoint contained no public keys').then(() => {
          jwtMock.verify()
          requestMock.verify()
        })
    })

    it('should return an error if the required key is missing', () => {
      body = { keys: [ body.keys[1] ] }
      jwtMock.expects('decode').withExactArgs('token', { complete: true }).returns(decodedToken)
      requestMock.expects('get')
        .withExactArgs(
          'https://cognito-idp.us-west-2.amazonaws.com/USER_POOL_ID/.well-known/jwks.json',
          sinon.match.func
        )
        .callsFake((url, cb) => {
          cb(null, { statusCode: '200' }, body)
        })
      return validator.validate('token')
        .should.be.rejectedWith('Required key is missing').then(() => {
          jwtMock.verify()
          requestMock.verify()
        })
    })

    it('should return an error if the token cannot be verified', () => {
      jwtMock.expects('decode').withExactArgs('token', { complete: true }).returns(decodedToken)
      requestMock.expects('get')
        .withExactArgs(
          'https://cognito-idp.us-west-2.amazonaws.com/USER_POOL_ID/.well-known/jwks.json',
          sinon.match.func
        )
        .callsFake((url, cb) => {
          cb(null, { statusCode: '200' }, body)
        })
      jwtMock.expects('verify')
        .withExactArgs('token', jwkToPem(body.keys[0]), sinon.match.object)
        .throws(new Error('PEM_read_bio_PUBKEY failed'))
      return validator.validate('token')
        .should.be.rejectedWith('Token is invalid: PEM_read_bio_PUBKEY failed').then(() => {
          jwtMock.verify()
          requestMock.verify()
        })
    })

    it('should return the decoded payload if the token is valid', () => {
      jwtMock.expects('decode').withExactArgs('token', { complete: true }).returns(decodedToken)
      requestMock.expects('get')
        .withExactArgs(
          'https://cognito-idp.us-west-2.amazonaws.com/USER_POOL_ID/.well-known/jwks.json',
          sinon.match.func
        )
        .callsFake((url, cb) => {
          cb(null, { statusCode: '200' }, body)
        })
      jwtMock.expects('verify')
        .withExactArgs('token', jwkToPem(body.keys[0]), sinon.match.object)
        .returns(decodedToken)
      return validator.validate('token').should.eventually.equal(decodedToken).then(() => {
        jwtMock.verify()
        requestMock.verify()
      })
    })
  })
})
