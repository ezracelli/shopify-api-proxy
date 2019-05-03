// /////////// Initial Setup /////////////

require('dotenv').config()

const axios = require('axios')
const bcrypt = require('bcrypt')
const cookie = require('cookie')
const cors = require('cors')
const crypto = require('crypto')
const express = require('express')
const nonce = require('nonce')()
const querystring = require('querystring')
const shopifyApiProxy = require('./router')

const {
  NODE_ENV,
  SHOPIFY_API_PUBLIC_KEY,
  SHOPIFY_APP_HOST,
  SHOPIFY_API_SECRET_KEY,
  PORT,
} = process.env

const corsProxy = NODE_ENV !== 'production'
  ? 'https://cors-anywhere.herokuapp.com/'
  : ''

const scopes = [
  'read_orders',
  'write_orders',
  'read_content',
  'write_content',
  'read_products',
  'write_products',
  'read_themes',
  'write_themes',
]

let state = `${nonce()}`

const app = express()

if (NODE_ENV !== 'production') {
  app.use(cors({ origin: true }))
}

// /////////// Helper Functions /////////////

const buildRedirectUri = () => `${SHOPIFY_APP_HOST}/shopify/callback`

const buildInstallUrl = (shop, state, redirectUri) => {
  const query = {
    client_id: SHOPIFY_API_PUBLIC_KEY,
    scope: scopes.join(','),
    state,
    redirect_uri: redirectUri,
  }

  return `${corsProxy}https://${shop}/admin/oauth/authorize?${querystring.stringify(query)}`
}

const generateEncryptedHash = params =>
  crypto
    .createHmac('sha256', SHOPIFY_API_SECRET_KEY)
    .update(params)
    .digest('hex')

const fetchAccessToken = async (shop, data) =>
  axios.post(`https://${shop}/admin/oauth/access_token`, data)

// /////////// Route Handlers /////////////

app.get('/', (req, res) => res.send('Hello, world!'))

// auth routes

app.get('/shopify', async (req, res) => {
  const shop = req.query.shop

  if (!shop) {
    return res.status(400).send('no shop')
  }

  state = `${nonce()}`
  const installShopUrl = buildInstallUrl(shop, state, buildRedirectUri())
  const stateCookie = await bcrypt.hash(state, 10)

  res.cookie('state', stateCookie)
  res.redirect(installShopUrl)
})

app.get('/shopify/callback', async (req, res) => {
  const { shop, code, state } = req.query
  res.cookie('shop', shop)

  const stateCookie = cookie.parse(req.headers.cookie).state

  const verified = await bcrypt.compare(state, stateCookie)
  if (!verified) {
    return res.status(401).send('cannot be verified')
  }

  const { hmac, ...params } = req.query
  const queryParams = querystring.stringify(params)
  const hash = generateEncryptedHash(queryParams)

  if (hash !== hmac) {
    return res.status(400).send('HMAC validation failed')
  }

  try {
    const data = {
      client_id: SHOPIFY_API_PUBLIC_KEY,
      client_secret: SHOPIFY_API_SECRET_KEY,
      code,
    }

    const tokenResponse = await fetchAccessToken(shop, data)

    // eslint-disable-next-line camelcase
    const { access_token } = tokenResponse.data
    res.cookie('access_token', access_token)

    res.send('Authorized!')
  } catch (err) {
    res.status(500).send('something went wrong')
  }
})

// api routes

app.use('/', shopifyApiProxy)

// /////////// Start the Server /////////////

const port = PORT || 80
app.listen(port, () => console.log(`listening on port ${port}`))
