const EventEmitter = require('events').EventEmitter

const BITBOXSDK = require('bitbox-sdk/lib/bitbox-sdk').default
const BITBOX = new BITBOXSDK()

// Options:
const hdPathString = "m/44'/145'"
const slpHdPathString = "m/44'/245'"
const type = 'HD Key Tree'

class HdKeyring extends EventEmitter {

  /* PUBLIC METHODS */

  constructor (opts = {}) {
    super()
    this.type = type
    this.deserialize(opts)
  }

  serialize () {
    return Promise.resolve({
      mnemonic: this.mnemonic,
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath,
      slpHdPath: this.slpHdPath,
    })
  }

  deserialize (opts = {}) {
    this.opts = opts || {}
    this.wallets = []
    this.slpWallets = []
    this.mnemonic = null
    this.root = null
    this.hdPath = hdPathString
    this.slpHdPath = slpHdPathString

    if (opts.mnemonic) {
      this._initFromMnemonic(opts.mnemonic)
    }

    if (opts.numberOfAccounts) {
      return this.addAccounts(opts.numberOfAccounts)
    }

    return Promise.resolve([])
  }

  addAccounts (numberOfAccounts = 1) {
    if (!this.root || !this.slpRoot) {
      const mnemonic = this.mnemonic ? this.mnemonic : BITBOX.Mnemonic.generate(128)
      this._initFromMnemonic(mnemonic)
    }

    const oldLen = this.wallets.length
    const newWallets = []
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = BITBOX.HDNode.derivePath(this.root, `${i}'/0/0`)
      const wallet = BITBOX.HDNode.toKeyPair(child)
      newWallets.push(wallet)
      this.wallets.push(wallet)
    }
    const hexWallets = newWallets.map((w) => {
      return this._getAddress(w)
    })

    // Add matching amount of SLP accounts
    const slpAccountsToAdd = this.wallets.length - this.slpWallets.length
    if (slpAccountsToAdd > 0) {
      this.addSlpAccounts(slpAccountsToAdd)
    }

    return Promise.resolve(hexWallets)
  }

  addSlpAccounts (numberOfAccounts = 1) {
    if (!this.root || !this.slpRoot) {
      const mnemonic = this.mnemonic ? this.mnemonic : BITBOX.Mnemonic.generate(128)
      this._initFromMnemonic(mnemonic)
    }

    const oldLen = this.slpWallets.length
    const newWallets = []
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = BITBOX.HDNode.derivePath(this.slpRoot, `${i}'/0/0`)
      const wallet = BITBOX.HDNode.toKeyPair(child)
      newWallets.push(wallet)
      this.slpWallets.push(wallet)
    }

    const hexWallets = newWallets.map((w) => {
      return this._getAddress(w)
    })
    return Promise.resolve(hexWallets)
  }

  getAccounts () {
    return Promise.resolve(this.wallets.map((w) => {
      return this._getAddress(w)
    }))
  }

  getSlpAccounts () {
    return Promise.resolve(this.slpWallets.map((w) => {
      return this._getAddress(w)
    }))
  }

  getAllAccounts () {
    const allWalelts = this.wallets.concat(this.slpWallets)
    const allAccounts = allWalelts.map((w) => {
      return this._getAddress(w)
    })
    return Promise.resolve(allAccounts)
  }

  // tx is an instance of the ethereumjs-transaction class.
  signTransaction (address, tx) {
    const wallet = this._getWalletForAccount(address)
    var privKey = wallet.getPrivateKey()
    tx.sign(privKey)
    return Promise.resolve(tx)
  }

  // For eth_sign, we need to sign transactions:
  // hd
  signMessage (withAccount, message) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = BITBOX.ECPair.toWIF(wallet)
    const signature = BITBOX.BitcoinCash.signMessageWithPrivKey(privKey, message)
    return Promise.resolve(signature)
  }

  // signMessage (withAccount, data) {
  //   const wallet = this._getWalletForAccount(withAccount)
  //   const message = ethUtil.stripHexPrefix(data)
  //   var privKey = wallet.getPrivateKey()
  //   var msgSig = ethUtil.ecsign(new Buffer(message, 'hex'), privKey)
  //   var rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
  //   return Promise.resolve(rawMsgSig)
  // }

  // // For personal_sign, we need to prefix the message:
  // signPersonalMessage (withAccount, msgHex) {
  //   const wallet = this._getWalletForAccount(withAccount)
  //   const privKey = ethUtil.stripHexPrefix(wallet.getPrivateKey())
  //   const privKeyBuffer = new Buffer(privKey, 'hex')
  //   const sig = sigUtil.personalSign(privKeyBuffer, { data: msgHex })
  //   return Promise.resolve(sig)
  // }

  // // personal_signTypedData, signs data along with the schema
  // signTypedData (withAccount, typedData) {
  //   const wallet = this._getWalletForAccount(withAccount)
  //   const privKey = ethUtil.toBuffer(wallet.getPrivateKey())
  //   const signature = sigUtil.signTypedData(privKey, { data: typedData })
  //   return Promise.resolve(signature)
  // }

  // // For eth_sign, we need to sign transactions:
  // newGethSignMessage (withAccount, msgHex) {
  //   const wallet = this._getWalletForAccount(withAccount)
  //   const privKey = wallet.getPrivateKey()
  //   const msgBuffer = ethUtil.toBuffer(msgHex)
  //   const msgHash = ethUtil.hashPersonalMessage(msgBuffer)
  //   const msgSig = ethUtil.ecsign(msgHash, privKey)
  //   const rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
  //   return Promise.resolve(rawMsgSig)
  // }

  exportKeyPair (address) {
    const wallet = this._getWalletForAccount(address)
    return Promise.resolve(wallet)
  }

  exportAccount (address) {
    const wallet = this._getWalletForAccount(address)
    const privateKey = BITBOX.ECPair.toWIF(wallet)
    return Promise.resolve(privateKey)
  }


  /* PRIVATE METHODS */

  _initFromMnemonic (mnemonic) {
    this.mnemonic = mnemonic

    const seed = BITBOX.Mnemonic.toSeed(mnemonic)
    this.hdWallet = BITBOX.HDNode.fromSeed(seed, 'bitcoincash')
    this.root = BITBOX.HDNode.derivePath(this.hdWallet, this.hdPath)
    this.slpRoot = BITBOX.HDNode.derivePath(this.hdWallet, this.slpHdPath)
  }

  _getAddress(keypair) {
    return BITBOX.ECPair.toCashAddress(keypair)
  }

  _getWalletForAccount (account) {
    const targetAddress = account
    const wallet = this.wallets.find((w) => {
      const address = this._getAddress(w)
      return (address === targetAddress)
    })
    
    // Check for SLP wallet if not found
    if (!wallet) {
      return this.slpWallets.find((w) => {
        const address = this._getAddress(w)
        return (address === targetAddress)
      })
    } else {
      return wallet
    }
  }
}

HdKeyring.type = type
module.exports = HdKeyring
