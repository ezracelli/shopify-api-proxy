const axios = require('axios')
const cookie = require('cookie')
const cors = require('cors')
const express = require('express')
const querystring = require('querystring')

const fetchData = async (shop, accessToken, route = '/shop', query) => {
  let endpoint = `https://${shop}/admin${route}.json`
  if (Object.keys(query).length) {
    endpoint += `?${querystring.stringify(query)}`
  }

  return axios(endpoint, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': accessToken,
    },
  })
}

// /////////// Shopify API Proxy Router /////////////
// ///// Adapted from @shopify/shopify-express //////

const blacklist = [
  '/application_charges',
  '/application_credits',
  '/carrier_services',
  '/fulfillment_services',
  '/recurring_application_charges',
  '/script_tags',
  '/storefront_access_token',
  '/webhooks',
  '/oauth',
]

const apiProxy = async (req, res, next) => {
  const { path: route } = req
  const query = querystring.parse(req.url.replace(/^[^?]*\?/, ''))
  console.log(query)

  // eslint-disable-next-line camelcase
  const { access_token: accessToken, shop } = cookie.parse(req.headers.cookie || '')

  if (!accessToken || !shop) {
    return res.status(401).send('unauthorized')
  }

  if (blacklist.includes(route)) {
    return res.status(403).send('endpoint blacklisted')
  }

  try {
    const data = await fetchData(shop, accessToken, route, query)
    res.send(data.data)
  } catch (err) {
    res.status(500).send('something went wrong')
  }
}

const router = express.Router()
router.use('/api', cors({ origin: true, credentials: true }), apiProxy)

module.exports = router
