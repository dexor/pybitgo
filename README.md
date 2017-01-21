# BitGo Python SDK

WARNING! This library is still in progress.

Alpha version of a [BitGo](https://bitgo.com) Python binding library. 


## Quick start

Installation:
```
pip install bitgo
```

Usage:

```python
from bitgo import BitGo

ACCESS_TOKEN = 'PUT YOUR LONG-LIVED TOKEN HERE'

b = BitGo(access_token=ACCESS_TOKEN, production=True)
b.get_wallets()

```


## Some command-line functionality

Get access token:

```
$ bitgo access_token
```

Send coins:

```
$ bitgo -a access_token -w wallet_id send 14Ys1oyysUH42rktapekucHYSqcW4Fse2K 0.01 
```

Get wallets:

```
$ bitgo get_wallets
```

And other.

## Testing

Fill in the `bitgo/tests/secrets.json` with actual data and run

```
$ pip install -r requirements-dev.txt
$ tox
```