# hdwallet-babyjub

Implementation of bip-32 & bip-39 for BabyJubJub curve.

## Usage

```js
const {Privkey, Pubkey} = require("hdwallet-babyjub");
const {k} = Privkey("shiver box little burden auto early shine vote dress symptom plate certain course open rely", "m/44'/0'/0'/0/0");
```