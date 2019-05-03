// /////////// Initial Setup /////////////

require('dotenv').config()

const axios = require('axios')
const cookie = require('cookie')
const cors = require('cors')
const crypto = require('crypto')
const express = require('express')
const nonce = require('nonce')()
const querystring = require('querystring')
const shopifyApiProxy = require('./router')

const corsProxy = process.env.NODE_ENV !== 'production'
  ? 'https://cors-anywhere.herokuapp.com/'
  : ''

const {
  SHOPIFY_API_PUBLIC_KEY,
  SHOPIFY_APP_HOST,
  SHOPIFY_API_SECRET_KEY,
  PORT,
} = process.env

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

const app = express()
app.use(cors({ origin: true }))

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

app.get('/shopify', (req, res) => {
  const shop = req.query.shop

  if (!shop) {
    return res.status(400).send('no shop')
  }

  const state = nonce()

  const installShopUrl = buildInstallUrl(shop, state, buildRedirectUri())

  res.cookie('state', state) // should be encrypted in production
  res.redirect(installShopUrl)
})

app.get('/shopify/callback', async (req, res) => {
  const { shop, code, state } = req.query
  res.cookie('shop', shop)

  const stateCookie = cookie.parse(req.headers.cookie).state

  if (state !== stateCookie) {
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

app.listen(PORT, () => console.log(`listening on port ${PORT}`))
