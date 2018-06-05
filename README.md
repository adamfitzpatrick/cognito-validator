# cognito-validator

Decodes and verifies AWS Cognito Identity Pool access tokens.  Decoding and verification is handled
by [`jsonwebtoken`](https://www.npmjs.com/package/jsonwebtoken), conversion from
[JSON Web Key](https://tools.ietf.org/html/rfc7517) by
[`jwk-to-pem`](https://www.npmjs.com/package/jwk-to-pem) and http requests by
[`request`](https://www.npmjs.com/package/request).

Using the system requires a valid user pool ID, associated client Id and matching AWS region:

```javascript
const CognitoValidator = require('cognito-validator')
const region = 'us-west-2'
const userPoolId = 'USER_POOL_ID'
const clientId = 'CLIENT_ID'

const validator = new CognitoValidator(region, userPoolId, clientId)

const token = /* Some valid JWT issued by AWS Cognito */

const verifiedToken = validator.validate(token)
```