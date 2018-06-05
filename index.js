const request = require('request')
const jwt = require('jsonwebtoken')
const jwkToPem = require('jwk-to-pem')

function parsePublicKeyResponse (kid, err, res, body, reject) {
  if (res.statusCode >= 400) {
    reject(new Error(`Unable to obtain keys: ${err.message}`))
  }
  if (!body.keys) {
    reject(new Error('Response from endpoint contained no public keys'))
  }
  const key = body.keys.filter(key => key.kid === kid)[0]
  if (!key) {
    reject(new Error('Required key is missing'))
  }
  return key
}

function doValidate (token, key, resolve, reject) {
  const pem = jwkToPem(key)
  try {
    const verified = jwt.verify(token, pem, {})
    resolve(verified)
  } catch (err) {
    err.message = `Token is invalid: ${err.message}`
    reject(err)
  }
}

class CognitoValidator {
  constructor (region, userPoolId, clientId) {
    this.region = region
    this.userPoolId = userPoolId
    this.clientId = clientId
  }

  getRegion () {
    return this.region
  }

  getUserPoolId () {
    return this.userPoolId
  }

  getClientId () {
    return this.clientId
  }

  getKeysUrl () {
    return `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}/.well-known/jwks.json`
  }

  validate (token) {
    const decodedToken = jwt.decode(token, { complete: true })
    if (!decodedToken || !(decodedToken.header && decodedToken.payload && decodedToken.signature)) {
      return Promise.reject(new Error('Object is not a JSON web token'))
    }
    const kid = decodedToken.header.kid
    return new Promise((resolve, reject) => {
      request.get(this.getKeysUrl(), (err, res, body) => {
        const key = parsePublicKeyResponse(kid, err, res, body, reject)
        doValidate(token, key, resolve, reject)
      })
    })
  }
}

module.exports = CognitoValidator
