/*!
 * Copyright (c) 2017, Park Alter (pseudonym)
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php
 *
 * https://github.com/park-alter/wmcc-explorer
 * wmcc_explorer.js - explorer plugin for wmcc_core.
 */

'use strict';

const moduleDir = '../../../app.asar/node_modules/';
const Core = require(moduleDir + 'wmcc-core');
const {Base} = Core.http;
const {digest, random, ccmp} = Core.crypto;
const {base58, Validator, fs, util, encoding} = Core.utils;
const {Network, consensus, policy} = Core.protocol;
const {Address} = Core.primitives;
const {Amount} = Core.wmcc;
const assert = require('assert');
const path = require('path');

const pkg = {
  version: 'v1.0.0-beta.1',
  url: 'https://github.com/worldmobilecoin/wmcc-core'
}

/**
 * Explorer Server
 * @extends {EventEmitter}
 */

 class Explorer extends Base {
  /**
   * Create a explorer server.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.config = new ExplorerOptions(options);

    this.network = this.config.network;
    this.logger = this.config.logger.context('explorer');
    this.node = this.config.node;
    this.parser = new Parser(this.node);

    this.__init();
  }

  static init(node) {
    const config = node.config;
    return new Explorer({
      network: node.network,
      logger: node.logger,
      node: node,
      prefix: config.prefix,
      ssl: config.bool('explorer-ssl'),
      keyFile: config.path('explorer-ssl-key'),
      certFile: config.path('explorer-ssl-cert'),
      host: config.str('explorer-http-host'),
      port: config.uint('explorer-http-port'),
      apiKey: config.str('explorer-api-key')
    });
  }

  __init() {
    this.on('request', (req, res) => {
      if (req.method === 'POST' && req.pathname === '/')
        return;

      this.logger.debug('Request for method=%s path=%s (%s).',
        req.method, req.pathname, req.socket.remoteAddress);
    });

    this.on('listening', (address) => {
      this.logger.info('Explorer server listening on %s (port=%d).',
        address.address, address.port);
    });

    this.initRouter();
    this.initSockets();
  }

  initRouter() {
    this.use(this.cors());
    this.use(this.public('../resource'));

    if (!this.config.noAuth) {
      this.use(this.basicAuth({
        password: this.config.apiKey,
        realm: 'node'
      }));
    }

    this.use(this.bodyParser({
      contentType: 'html'
    }));

    const options = {
      parser: this.parser
    }

    this.get('/', async (req, res) => {
      const template = new Template(options);

      template.append({
        block: '1',
        module: 'block',
        category: 'latest',
        data: await this.parser.blockLatest(this.config.port)
      });

      template.append({
        block: '3',
        module: 'transaction',
        category: 'recent',
        data: this.parser.transactionRecent()
      });

      res.send(200, template.get(), 'html');
    });

    this.get('/block/:block', async (req, res) => {
      const template = new Template(options);
      const valid = req.valid();
      const hash = valid.get('block');

      template.append({
        block: '1',
        module: 'block',
        category: 'summary',
        data: await this.parser.blockSummary(hash)
      });

      template.append({
        block: '3',
        module: 'transaction',
        category: 'details',
        data: await this.parser.transactionBlock(hash)
      });

      res.send(200, template.get(), 'html');
    });

    this.get('/tx/:hash', async (req, res) => {
      const template = new Template(options);
      const valid = req.valid();
      const hash = valid.hash('hash');
      const summary = await this.parser.transactionSummary(hash);

      template.append({
        block: '1',
        module: 'transaction',
        category: 'summary',
        data: summary
      });

      template.append({
        block: '3',
        module: 'transaction',
        category: 'details',
        data: await this.parser.transactionBlock(summary.txn_block_hash)
      });

      template.append({
        block: '4',
        html: await this.parser.transactionScript(hash)
      });

      res.send(200, template.get(), 'html');
    });

    this.get('/address/:index/:address', async (req, res) => {
      const template = new Template(options);
      const valid = req.valid();
      const index = valid.u32('index');
      const address = valid.str('address');

      await this.parser.setAddress(address);

      template.append({
        block: '1',
        module: 'address',
        category: 'summary',
        data: this.parser.addressSummary()
      });

      template.append({
        block: '3',
        module: 'transaction',
        category: 'details',
        data: await this.parser.addressTransaction(index)
      });

      res.send(200, template.get(), 'html');
    });

    this.get('/search/:hash', async (req, res) => {
      const template = new Template(options);
      const valid = req.valid();
      const types = await this.parser.search(valid);

      for(let type of types)
        template.append(type);

      res.send(200, template.get(), 'html');
    });

    this.get('/latest/:max', async (req, res) => {
      const valid = req.valid();
      const max = valid.u32('max');

      const blocks = await this.parser.blockLatest(this.config.port, max);
      res.send(200, blocks, 'json');
    });
  }

  public(staticPath) {
    return async (req, res) => {
      const filePath = path.join(__dirname, staticPath, req.url);
      const ext = path.extname(filePath).substr(1);

      if (!ext)
        return;

      fs.exists(filePath, function(exists) {
        if(!exists)
          res.send(404);
      });

      this.get(req.url, async (req, res) => {
        const file = fs.readFileSync(filePath);
        res.send(200, file, ext);
      });
    };
  }

  initSockets() {      
    let IOServer;
    if (!this.io) {
      try {
        IOServer = require(moduleDir + 'socket.io');
      } catch (e) {
        ;
      }
    }

    if (!IOServer)
      return;

    this.io = new IOServer({
      transports: ['websocket'],
      serveClient: false
    });

    this.event = new Event(this.node, this.io);

    this.io.attach(this.server);

    this.io.on('connection', (ws) => {
      this.addSocket(ws);
    });

    this.on('socket', (socket) => {
      this.handleSocket(socket);
    });
  }

  handleSocket(socket) {
      socket.hook('auth', (args) => {
      if (socket.auth)
        throw new Error('Already authed.');

      if (!this.config.noAuth) {
        const valid = new Validator([args]);
        const key = valid.str(0, '');

        if (key.length > 255)
          throw new Error('Invalid API key.');

        const data = Buffer.from(key, 'ascii');
        const hash = digest.hash256(data);

        if (!ccmp(hash, this.config.apiHash))
          throw new Error('Invalid API key.');
      }

      socket.auth = true;

      this.logger.info('Successful auth from %s.', socket.remoteAddress);
      this.handleAuth(socket);

      return null;
    });

    socket.emit('version', {
      version: pkg.version,
      network: this.network.type
    });
  }
}

/**
 * Template
 */
class Template {  
  /**
   * Create a template.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.style = 'default';
    this.publicPath = '../resource/template';
    this.modulePath = '../resource/module';
    this.parser = null;

    if (options)
      this.fromOptions(options);

    this.init();
  }

  init() {
    this.template = fs.readFileSync(path.join(this.getTemplatePath(), 'index.htm'), 'utf8');
    this.setHeader();
    this.setFooter();
  }

  fromOptions(options) {
    assert(options, 'Options required.');

    if (options.style != null) {
      assert(typeof options.style === 'string', 'Style name must be a string.');
      this.setStyle(options.style);
    }

    if (options.public != null) {
      assert(typeof options.public === 'string', 'Public path must be a string.');
      this.publicPath = options.public;
    }

    if (options.module != null) {
      assert(typeof options.module === 'string', 'Module path must be a string.');
      this.modulePath = options.module;
    }

    if (options.parser != null) {
      assert(typeof options.parser === 'object', 'Parser must be an object.');
      this.parser = options.parser;
    }
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  get() {
    assert(this.template, 'Template not found!');
    return this.template;
  }

  getTemplatePath(style) {
    const name = style || this.style;
    return path.join(__dirname, this.publicPath, name);
  }

  setStyle(style) {
    assert(style, 'Style name is required.')
    if (fs.existsSync(getTemplatePath(style)))
      this.style = style;
  }

  setHeader() {
    this.append({
      block: 'header',
      module: 'header',
      category: 'navigation'
    });
  }

  setFooter() {
    this.append({
      block: 'footer',
      module: 'footer',
      category: 'navigation'
    });
  }

  append(options) {
    assert(options.block, 'Block position is required.');

    if (options.module) {
      let content = this.getModule(options.module, options.category);
      if (options.data)
        content = this.test(options.data, content);

      this.template = this.template.replace(`<!--__${options.block}__-->`, content);
    }else if (options.html) {
      this.template = this.template.replace(`<!--__${options.block}__-->`, options.html);
    }
  }

  getModule(module, category) {
    return fs.readFileSync(path.join(__dirname, this.modulePath, module, `${category}.htm`), 'utf8');
  }

  test(data, content) {
    assert(typeof data === 'object', 'Data must be an object.');
    for (const prop in data) {
      if (Array.isArray(data[prop])) {
        let temp = '';
        const test = content.match(new RegExp("<!--LOOP::"+prop+"-->([\\s\\S]*?)<!--END_LOOP-->"));
        for (const obj of data[prop]) {
          temp += this.replace(obj, test[1])
        }
        content = content.replace(test[0], temp);
      } else if (typeof data[prop] === 'object') {
        if (data[prop]['empty']) {
          const test = content.match(new RegExp("<!--LOOP::"+prop+"-->([\\s\\S]*?)<!--END_LOOP-->"));
          content = content.replace(test[0], data[prop]['empty']);
        }
      } else {
        content = content.replace(new RegExp(`{{${prop}}}`,"g"), data[prop]);
      }
    }
    return content;
  }

  replace(data, content) {
    assert(typeof data === 'object', 'Data must be an object.');

    for (const prop in data) {
      content = content.replace(new RegExp(`{{${prop}}}`,"g"), data[prop]);
    }
    return content;
  }
}

/**
 * Data Parser
 */

class Parser {
  /**
   * Create event emitter for browser.
   * @constructor
   * @param {Object} options
   */

  constructor(node) {
    this.node = node;
    this.chain = node.chain;
    this.mempool = node.mempool;
    this.pool = node.pool;
    this.fees = node.fees;
    this.miner = node.miner;
    this.rpc = node.rpc;

    this.address = {};
  }

  async blockLatest(port, max = 10) {
    const blocks = new Array();
    const tip = this.chain.height;

    for(let i=tip; i>(tip-max) && i > -1; i--) {
      const entry = await this.chain.getEntry(i);
      const block = await this.chain.getBlock(entry.hash);
      blocks.push({
        block_height: entry.height,
        block_timestamp: entry.time,
        block_time: age(entry.time),
        block_txs_length: block.txs.length,
        block_output: Amount.wmcc(block.getClaimed()),
        block_size: block.getVirtualSize()/1000,
        block_weight: block.getWeight()/1000          
      });
    }

    return {
      blocks: blocks,
      http_port: port
    }
  }

  async blockSummary(hash) {
    enforce(typeof hash === 'string', 'Hash or height required.');
    enforce(!this.chain.options.spv, 'Cannot get block in SPV mode.');

    if (hash.length === 64)
      hash = util.revHex(hash);
    else {
      enforce(/^[0-9]+$/.test(hash), 'Height must be an integer.');
      hash = parseInt(hash, 10);
    }

    const entry = await this.chain.getEntry(hash);
    const block = await this.chain.getBlock(entry.hash);

    let total = 0;
    let fee;
    for (let tx of block.txs) {
      for (let vout of tx.outputs) {
        total += vout.value;
        if(tx.isCoinbase()) {
          const reward = consensus.getReward(entry.height);
          const output = tx.outputs[0].value;
          fee = `${Amount.wmcc((output-reward), true)} wmcc`;
        }
      }
    }

    if (entry.height === 0) fee = `0 wmcc`;

    const next = await this.node.chain.getNextHash(entry.hash);

    return {
      block_height: entry.height,
      block_txn_count: block.txs.length,
      block_txn_timestamp: new Date(entry.time * 1000).format("F j, Y, h:i:s A"),
      block_output: `${Amount.wmcc(total, true)} wmcc`,
      block_confirmation: this.chain.height - entry.height + 1,
      block_txn_fee: fee,
      block_version: `0x${util.hex32(entry.version)}`,
      block_hash: entry.rhash(),
      block_prev: entry.prevBlock !== encoding.NULL_HASH ? util.revHex(entry.prevBlock) : '',
      block_next: next ? util.revHex(next) : '',
      block_merkle: util.revHex(entry.merkleRoot),
      block_chainwork: entry.chainwork.toString('hex', 64),
      block_difficulty: toDifficulty(entry.bits),
      block_bits: entry.bits,
      block_nonce: entry.nonce,
      block_size: `${block.getVirtualSize()} bytes`,
      block_weight: `${block.getWeight()} bytes`
    }
  }

  async transactionSummary(hash) {
    enforce(hash, 'Hash is required.');
    enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

    hash = util.revHex(hash);

    const {tx, time, mtime, height, block} = await this.chain.getMeta(hash);
    const date = new Date((time||mtime) * 1000).format("M d, Y, g:i:s A");
    const {details, totalout, totalin} = await this.toDetails(tx);

    let totalinput = 0,
        fee = 0;

    if (!tx.isCoinbase()) {
      totalinput = Amount.wmcc(totalin, true);
      fee = totalin-totalout;
    }

    const rate = fee > 0 ? Amount.wmcc(policy.getRate(tx.getVirtualSize(), fee), true) : 0;
    const wrate = fee > 0 ? Amount.wmcc(policy.getRate(tx.getWeight(), fee), true) : 0;
    const blkheight = height < 0 ? '': height;
    const blkhash = height < 0 ? '': util.revHex(block);
    const confirm = height < 0 ? 'Unconfirmed Transaction': this.chain.height - height + 1;

    return {
      txn_id: util.revHex(tx.txid()),
      txn_virtual_size: tx.getVirtualSize(),
      txn_total_input: totalinput,
      txn_weight: tx.getWeight(),
      txn_total_output: Amount.wmcc(totalout, true),
      txn_date: date,
      txn_fee: fee,
      txn_block_height: blkheight,
      txn_block_hash: blkhash,
      txn_rate: rate,
      txn_confirmation: confirm,
      txn_wrate: wrate
    }
  }

  transactionRecent(max = 10) {
    let txns = new Array();

    if (this.mempool.map.size) {
      let count = 0, max = 10;
      this.mempool.map.forEach((value, hash) => {
        if (max > count) {
          txns.push({
            txn_hash: hash,
            txn_size: value.size,
            txn_value: Amount.wmcc(value.value, true)
          });
        } else return;
      });
    } else {
      txns = { empty: `<tr class='norecord'><td colspan="3">No recent transaction found.</td></tr>` };
    }

    return {
      transactions: txns
    }
  }

  async transactionHash(hash){
    const {height} = await this.chain.getMeta(hash);
    return await this.transactionBlock(height);
  }

  async transactionBlock(hash){
    enforce(typeof hash === 'string', 'Hash or height required.');
    enforce(!this.chain.options.spv, 'Cannot get block in SPV mode.');

    let txns = new Array();
    let misc = null;

    if (hash.length === 64)
      hash = util.revHex(hash);
    else
      hash = parseInt(hash, 10);

    const {time, txs} = await this.chain.getBlock(hash);

    for (let tx of txs) {
      const {details, totalout, totalin} = await this.toDetails(tx);

      if (tx.isCoinbase())
        misc = `(Size: ${tx.getVirtualSize()} bytes)`;
      else
        misc = `(Fee: ${Amount.wmcc((totalin-totalout), true)} wmcc, Size: ${tx.getVirtualSize()} bytes)`;

      txns.push({
        txn_id: util.revHex(tx.txid()),
        txn_date: new Date(time * 1000).format("M d, Y, g:i:s A"),
        txn_class: '',
        txn_title: '',
        txn_misc: misc,
        txn_details: toTxTable(details, null),
        txn_total: `${Amount.wmcc(totalout, true)} wmcc`
      });
    }

    return {
      transactions: txns,
      txn_page: ''
    }
  }

  async transactionScript (hash) {
    enforce(hash, 'Hash is required.');
    enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

    let html = '';
    let txns = new Array();
    let misc = null;

    hash = util.revHex(hash);

    const {tx} = await this.chain.getMeta(hash);
    const {inputs, outputs} = tx;

    html += `<div class="scripts">`;
    if (inputs[0].getType() === 'coinbase')
      html += `<h2>Coinbase</h2>`;
    else
      html += `<h2>Input Scripts</h2><div>`;

    for (let input of inputs) {
      const script = input.script.toJSON();
      const witness = input.witness.toString();
      const commitment = input.script.getCommitment();
      if (script) {
        html += `<h3>${input.script.getInputTypeVal()}</h3>`;
        html += `<p>${script}</p>`;
      }
      if (commitment) {
        html += `<h3>Commitment hash</h3>`;
        html += `<p>${commitment.toString('hex')}</p>`;
      }
      if (witness) {
        html += `<h3>${input.witness.getInputTypeVal()}</h3>`;
        html += `<p>${witness}</p>`;
      }
    }

    html += `</div><div class="scripts"><h2>Output Scripts</h2>`;
    for (let output of outputs) {
      html += `<h3>${output.getType()}</h3>`;
      html += `<span>${output.script.toString()}</span>`;
      const commitment = output.script.getCommitment();
      if (commitment) {
        html += `<h3>Commitment hash</h3>`;
        html += `<span>${commitment.toString('hex')}</span>`;
      }
    }

    return `${html}</div>`;
  }

  async setAddress(address) {
    enforce(address, 'Address is required.');
    enforce(!this.chain.options.spv, 'Cannot get TX in SPV mode.');

    const addr = Address.fromString(address);
    const metatx = await this.chain.getMetaByAddress(address);
    const coins = await this.chain.getCoinsByAddress(address);
    const memtx = await this.mempool.getAllMetaByAddress(addr);

    metatx.push.apply(metatx, filtermeta(memtx));
    metatx.sort(compare);

    this.address.metatx = metatx;
    this.address.coins = coins;
    this.address.addr = addr;
  }

  addressSummary() {
    enforce(this.address, 'Address not set.');

    const {metatx, coins, addr} = this.address;

    let balance = 0;
    for (let coin of coins)
      balance += coin.value;

    let received = 0;
    for (let meta of metatx) {
      for (let output of meta.tx.outputs) {
        let out = output.getAddress() ? output.getAddress().hash: Buffer.alloc(0);
        if (addr.hash.equals(out))
          received += output.value;
      }
    }

    return {
      address: addr.toString(),
      address_txn_length: metatx.length,
      address_received: Amount.wmcc(received, true),
      address_hash: addr.hash.toString('hex'),
      address_balance: Amount.wmcc(balance, true)
    }
  }

  async addressTransaction(index, max = 50) {
    enforce(typeof index === 'number', 'Index of address page is required.');
    enforce(!this.chain.options.spv, 'Cannot get block in SPV mode.');

    let txns = new Array();
    let misc = null;

    const {metatx, addr} = this.address;
    const offset = max*index;
    const until = offset > metatx.length ? metatx.length : offset;

    if (max*(index-1) > metatx.length || index === 0)
      return {
        transactions: { empty: `<tr><td colspan="3">No transaction found on page ${index}.</td></tr>` }
      }

    for (let i=offset-max; i<until; i++) {
      const {details, totalout, totalin} = await this.toDetails(metatx[i].tx);

      if (metatx[i].tx.isCoinbase())
        misc = `(Size: ${metatx[i].tx.getVirtualSize()} bytes)`;
      else
        misc = `(Fee: ${Amount.wmcc((totalin-totalout), true)} wmcc, Size: ${metatx[i].tx.getVirtualSize()} bytes)`;

      txns.push({
        txn_id: util.revHex(metatx[i].tx.txid()),
        txn_date: new Date((metatx[i].time||metatx[i].mtime) * 1000).format("M d, Y, g:i:s A"),
        txn_class: metatx[i].block ? "": " red",
        txn_title: metatx[i].block ? "": "Unconfirmed transaction",
        txn_misc: misc,
        txn_details: toTxTable(details, addr.toString()),
        txn_total: `${Amount.wmcc(totalout, true)} wmcc`
      });
    }

    return {
      transactions: txns,
      txn_page: page(metatx.length, index, max, this.address.addr)
    }
  }

  async search(valid) {
    const info = [];
    let hash;

    /* find block */
    try {
      hash = valid.get('hash');
      const blksummary = await this.blockSummary(hash);
      const blktxn = await this.transactionBlock(hash);

      info.push({
        block: '1',
        module: 'block',
        category: 'summary',
        data: blksummary
      });

      info.push({
        block: '3',
        module: 'transaction',
        category: 'details',
        data: blktxn
      });
    } catch (e){ ; }

    /* find tx */
    try {
      hash = valid.hash('hash');
      const txnsummary = await this.transactionSummary(hash);
      const txnblk = await this.transactionBlock(txnsummary.txn_block_hash);

      info.push({
        block: '1',
        module: 'transaction',
        category: 'summary',
        data: txnsummary
      });

      info.push({
        block: '3',
        module: 'transaction',
        category: 'details',
        data: txnblk
      });

      info.push({
        block: '4',
        html: await this.transactionScript(hash)
      });
    } catch (e){ ; }

    /* find address */
    try {
      hash = valid.str('hash');
      await this.setAddress(hash);

      info.push({
        block: '1',
        module: 'address',
        category: 'summary',
        data: this.addressSummary()
      });

      info.push({
        block: '3',
        module: 'transaction',
        category: 'details',
        data: await this.addressTransaction(1)
      });
    } catch (e){ ; }

    enforce(info.length, `Unable to find ${hash}`);

    return info;
  }

  async toDetails(tx) {
    let totalout = 0,
        totalin = 0,
        outputs = null;

    const details = {
      output: {},
      input: {},
      pending: []
    }

    for (let vin of tx.inputs) {
      if (tx.isCoinbase())
        continue;

      const chaintx = await this.chain.getTX(vin.prevout.hash);
      if (chaintx)
        outputs = chaintx.outputs;
      else {
        outputs = await this.mempool.getTX(vin.prevout.hash).outputs;
        details.pending.push(`${outputs[vin.prevout.index].getAddress()}`);
      }

      const input = outputs[vin.prevout.index].value;
      const inaddr = `${outputs[vin.prevout.index].getAddress()}`;

      if (details.input[inaddr])
        details.input[inaddr] += input;
      else
        details.input[inaddr] = input;

      totalin += input;
    }

    for (let vout of tx.outputs) {
      const outaddr = vout.script.getAddress() ? `${vout.script.getAddress()}`: 'unknown';
      if (details.output[outaddr])
        details.output[outaddr] += vout.value;
      else
        details.output[outaddr] = vout.value;

      totalout += vout.value;
    }

    return {
      details: details,
      totalin: totalin,
      totalout: totalout
    }
  }
}

/**
 * Event emitter
 */

class Event {
  /**
   * Create event emitter for browser.
   * @constructor
   * @param {Object} options
   */

  constructor(node, io) {
    this.node = node;
    this.chain = node.chain;
    this.mempool = node.mempool;
    this.io = io;

    this.init();
  }

  init() {
    this.chain.on('block', (block, entry)=>{
      const data = {
        height: entry.height,
        timestamp: entry.time,
        time: age(entry.time),
        txs_length: block.txs.length,
        output: Amount.wmcc(block.getClaimed()),
        size: block.getVirtualSize()/1000,
        weight: block.getWeight()/1000
      }
      this.io.emit('block', data);
    });

    this.mempool.on('tx', (tx)=>{
      let value = 0;
      for (let output of tx.outputs)
        value += output.value;

      const data = {
        hash: tx.hash('hex'),
        size: tx.getSize(),
        value: Amount.wmcc(value, true)
      }
      this.io.emit('tx', data);
    });
  }
}

/**
 * Explorer Options
 */

class ExplorerOptions {
  /**
   * Create explorer options.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.network = Network.primary;
    this.logger = null;
    this.node = null;
    this.apiKey = base58.encode(random.randomBytes(20));
    this.apiHash = digest.hash256(Buffer.from(this.apiKey, 'ascii'));
    this.noAuth = true;

    this.prefix = null;
    this.host = '127.0.0.1';
    this.port = 8090;
    this.ssl = false;
    this.keyFile = null;
    this.certFile = null;

    this.fromOptions(options);
  }

  fromOptions(options) {
    assert(options, 'Options are required.');
    assert(options.node && typeof options.node === 'object', 'Node is required.');

    this.node = options.node;
    this.network = options.node.network;
    this.logger = options.node.logger;

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
    }

    if (options.apiKey != null) {
      assert(typeof options.apiKey === 'string',
        'API key must be a string.');
      assert(options.apiKey.length <= 255,
        'API key must be under 256 bytes.');
      assert(util.isAscii(options.apiKey),
        'API key must be ascii.');
      this.apiKey = options.apiKey;
      this.apiHash = digest.hash256(Buffer.from(this.apiKey, 'ascii'));
    }

    if (options.noAuth != null) {
      assert(typeof options.noAuth === 'boolean');
      this.noAuth = options.noAuth;
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
      this.keyFile = path.join(this.prefix, 'key.pem');
      this.certFile = path.join(this.prefix, 'cert.pem');
    }

    if (options.host != null) {
      assert(typeof options.host === 'string');
      this.host = options.host;
    }

    if (options.port != null) {
      assert(util.isU16(options.port), 'Port must be a number.');
      this.port = options.port;
    }

    if (options.ssl != null) {
      assert(typeof options.ssl === 'boolean');
      this.ssl = options.ssl;
    }

    if (options.keyFile != null) {
      assert(typeof options.keyFile === 'string');
      this.keyFile = options.keyFile;
    }

    if (options.certFile != null) {
      assert(typeof options.certFile === 'string');
      this.certFile = options.certFile;
    }

    // Allow no-auth implicitly
    // if we're listening locally.
    if (!options.apiKey) {
      if (this.host === '127.0.0.1' || this.host === '::1')
        this.noAuth = true;
    }

    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }
}

/*
 * Helpers
 */

function enforce(value, msg) {
  if (!value) {
    const err = new Error(msg);
    err.statusCode = 400;
    throw err;
  }
}

function age(time, bool) {
  let d = bool ? time : Math.abs(Date.now()/1000 - time);
  let o = '';
  let r = {};
  let c = 0;
  let z = '';
  const s = {
    year: 31536000,
    month: 2592000,
    week: 604800,
    day: 86400,
    hour: 3600,
    minute: 60,
    second: 1
  }

  Object.keys(s).forEach(function(i){
    r[i] = Math.floor(d / s[i]);
    d -= r[i] * s[i];
    if (r[i] && c<2) {
      z = (r[i] < 10) ? `0${r[i]}`: r[i];
      c++;
      o += ` ${z} ${i}${r[i] > 1 ? 's':''}`;
    }
  });
  if (!o)
    return 'Just now';
  return `${o}${bool ? '':' ago'}`;
}

function toDifficulty(bits) {
  let shift = (bits >>> 24) & 0xff;
  let diff = 0x0000ffff / (bits & 0x00ffffff);

  while (shift < 29) {
    diff *= 256.0;
    shift++;
  }

  while (shift > 29) {
    diff /= 256.0;
    shift--;
  }

  return diff.toFixed(12);
}

function compare(a,b) {
  const atime = a.time ? a.time: a.mtime;
  const btime = b.time ? b.time: b.mtime;
  return (atime < btime) ? 1 : ((btime < atime) ? -1 : 0);
}

function filtermeta(meta) {
  return meta.filter( function(e,i,s) {
    return s[i].tx._hhash !== e.tx._hhash;
  });
}

function toTxTable(details, address, index = 1) {
  let html = '',
      type = false;

  if (Object.keys(details.input).length) {
    for (let input in details.input) {
      if (input === address)
        html += `<div><span>${input}</span>`, type = true;
      else if (details.pending.includes(input))
        html += `<div><a class='red address' title='Output from unconfirmed transaction' href="/address/${index}/${input}">${input}</a></span>`;
      else
        html += `<div><a class='address' href="/address/${index}/${input}">${input}</a>`;
      html += `<span class='value'>${Amount.wmcc(details.input[input], true)} wmcc</span></div>`;
    }
  } else
    html += `<div><span class='coinbase'>No Inputs (Newly Generated Coins)</span></div>`;

  html += `</td><td><i class="glyph-icon flaticon-${type?'out red':'in green'}"></i></td><td>`;

  for (let output in details.output) {
    html += `<div>`;
    if (output === 'unknown')
      html += `<a class='unparsed'>Unparsed output address</a>`;
    else if (output === address)
      html += `<div><a class='address'>${output}</a>`;
    else
      html += `<a class='address' href="/address/${index}/${output}">${output}</a>`;

    html += `<span class='value'>${Amount.wmcc(details.output[output], true)} wmcc</span></div>`;
  }

  return html;
}

function page(total, index, max, address) {
  if (total <= max)
    return '';

  let html = '';
  const last = Math.ceil(total/max);
  const {start, end} = median(index, last, 10);

  html += `<div class="page"><a ${(index === 1) ? 'class="disable"' : 'href="/address/'+(index-1)+'/'+address+'"'}>&#9668;</a>`;
  for(let i=start; i<end; i++) {
    html += `<a ${(index === i) ? 'class="active"' : 'href="/address/'+(i)+'/'+address+'"'}>${i}</a>`;
  }
  html += `<a ${(index+1 > last) ? 'class="disable"' : 'href="/address/'+(index+1)+'/'+address+'"'}>&#9658;</a></div>`;

  return html;
}

function median(c, m, l) {
  let s = Math.max(1, c-(l/2));
  const e = Math.min(s+l, m+1);
  s = Math.max(1,Math.min(e-l, e));
  return {start: s, end: e};
}

/*
 * Expose
 */

module.exports = Explorer;