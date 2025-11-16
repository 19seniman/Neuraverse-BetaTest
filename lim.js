const { ethers } = require('ethers');
const axios = require('axios');
const fs = require('fs');
const readline = require('readline');
const dotenv = require('dotenv');
const { HttpsProxyAgent } = require('https-proxy-agent');

dotenv.config();

const colors = {
  reset: '\x1b[0m', cyan: '\x1b[36m', green: '\x1b[32m', yellow: '\x1b[33m',
  red: '\x1b[31m', white: '\x1b[37m', bold: '\x1b[1m',
};
const logger = {
  info: (msg) => console.log(`${colors.white}[➤] ${msg}${colors.reset}`),
  warn: (msg) => console.log(`${colors.yellow}[⚠] ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}[✗] ${msg}${colors.reset}`),
  success: (msg) => console.log(`${colors.green}[✅] ${msg}${colors.reset}`),
  loading: (msg) => console.log(`${colors.cyan}[⟳] ${msg}${colors.reset}`),
  step: (msg) => console.log(`\n${colors.cyan}${colors.bold}[➤] ${msg}${colors.reset}`),
  banner: () => {
    console.log(`${colors.cyan}${colors.bold}`);
    console.log(`---------------------------------------------`);
    console.log(`     19Seniman from Insiders      `);
    console.log(`---------------------------------------------${colors.reset}\n`);
  },
};

const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const ask = (rl, q) => new Promise((res) => rl.question(q, res));
const getRandomAmount = (min, max) => (Math.random() * (max - min) + min).toFixed(5);
const getUA = () => ([
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
])[Math.floor(Math.random() * 2)];

async function showCountdown(durationMs, message) {
    logger.info(message);
    let remaining = durationMs;
    while (remaining > 0) {
        const hours = Math.floor(remaining / 3600000);
        const minutes = Math.floor((remaining % 3600000) / 60000);
        const seconds = Math.floor((remaining % 60000) / 1000);
        
        const timeStr = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        
        process.stdout.write(`${colors.cyan}[⟳] ${message} | Next run in: ${timeStr}${colors.reset}\r`);
        
        await delay(1000);
        remaining -= 1000;
    }
    process.stdout.write('\n');
    logger.success('Countdown finished. Starting next run...');
}

function formatProxy(p) {
  if (!p || !p.includes('://')) return p;
  const [proto, rest] = p.split('://');
  const atCount = (rest.match(/@/g) || []).length;
  if (atCount !== 1) return p;
  const [a, b] = rest.split('@');
  if (b.includes(':')) return `${proto}://${b}@${a}`;
  return p;
}

async function fetchAvailableTokens() {
    logger.info('Fetching available swap tokens...');
    try {
        const endpoint = "https://api.goldsky.com/api/public/project_cmc8t6vh6mqlg01w19r2g15a7/subgraphs/analytics/1.0.1/gn";
        const query = `query AllTokens { tokens { id symbol name decimals } }`;
        const body = { operationName: "AllTokens", variables: {}, query: query };
        const response = await axios.post(endpoint, body);
        const tokens = response.data.data.tokens;
        const uniqueTokens = new Map();
        for (const token of tokens) {
            if (!token.symbol || token.symbol.includes(' ')) continue;
            const symbol = token.symbol.toUpperCase();
            if (!uniqueTokens.has(symbol)) {
                uniqueTokens.set(symbol, {
                    address: token.id,
                    symbol: symbol,
                    decimals: parseInt(token.decimals, 10),
                });
            }
        }
        if (uniqueTokens.has('WANKR')) {
             uniqueTokens.set('ANKR', { ...uniqueTokens.get('WANKR'), symbol: 'ANKR' });
        }
        logger.success(`Found ${uniqueTokens.size} unique swappable tokens.`);
        return Array.from(uniqueTokens.values()).sort((a,b) => a.symbol.localeCompare(b.symbol));
    } catch (e) {
        logger.error(`Failed to fetch tokens: ${e.message}`);
        return [];
    }
}

async function runTaskWithRetries(taskFn, taskName, maxRetries = 3) {
    logger.step(`Starting task: ${taskName}`);
    for (let i = 0; i < maxRetries; i++) {
        try {
            await taskFn();
            logger.success(`Task "${taskName}" completed successfully.`);
            return;
        } catch (error) {
            logger.warn(`Attempt ${i + 1}/${maxRetries} for task "${taskName}" failed: ${error.message}`);
            if (i === maxRetries - 1) {
                logger.error(`Task "${taskName}" failed after ${maxRetries} attempts. Moving to the next task.`);
            } else {
                await delay(5000);
            }
        }
    }
}

const NEURA_RPC = 'https://testnet.rpc.neuraprotocol.io/';
const SEPOLIA_RPC = 'https://ethereum-sepolia-rpc.publicnode.com/';
const NEURA_CHAIN_ID = 267;
const SEPOLIA_CHAIN_ID = 11155111;

const CONTRACTS = {
  NEURA: {
    SWAP_ROUTER: '0x5AeFBA317BAba46EAF98Fd6f381d07673bcA6467',
    WANKR: '0xbd833b6ecc30caeabf81db18bb0f1e00c6997e7a', 
    ZTUSD: '0x9423c6c914857e6daaace3b585f4640231505128', 
    BRIDGE: '0xc6255a594299F1776de376d0509aB5ab875A6E3E', 
  },
  SEPOLIA: {
    BRIDGE: '0xc6255a594299F1776de376d0509aB5ab875A6E3E', 
    TANKR: '0xB88Ca91Fef0874828e5ea830402e9089aaE0bB7F', 
  },
};

const ABIS = {
  SWAP_ROUTER: ['function multicall(bytes[] data) payable returns (bytes[] results)'],
  ERC20: [
    'function approve(address spender, uint256 amount) external returns (bool)',
    'function balanceOf(address account) external view returns (uint256)',
    'function allowance(address owner, address spender) external view returns (uint256)',
    'function decimals() external view returns (uint8)',
    'function transfer(address to, uint256 amount) external returns (bool)',
  ],
  NEURA_BRIDGE: ['function deposit(address _recipient, uint256 _chainId) payable'],
  SEPOLIA_BRIDGE: ['function deposit(uint256 assets, address receiver) external'],
  BRIDGE_CLAIM: ['function claim(bytes encodedMessage, bytes[] messageSignatures) external'],
};

const API_ENDPOINTS = {
  BASE: 'https://neuraverse-testnet.infra.neuraprotocol.io/api',
  AUTH_BASE: 'https://privy.neuraprotocol.io/api/v1', 
  get AUTH_INIT() { return `${this.AUTH_BASE}/siwe/init`; },
  get AUTH_AUTHENTICATE() { return `${this.AUTH_BASE}/siwe/authenticate`; },
  get EVENTS() { return `${this.BASE}/events`; },
  get ACCOUNT() { return `${this.BASE}/account`; },
  get FAUCET() { return `https://neuraverse.neuraprotocol.io/api/faucet`; },
  get VALIDATORS() { return `${this.BASE}/game/validators/`; },
  get CHAT() { return `${this.BASE}/game/chat/validator/`; },
  get TASKS() { return `${this.BASE}/tasks`; },
  taskClaim(taskId) { return `${this.TASKS}/${taskId}/claim`; },
  claimList(recipient, page = 1, limit = 20) {
    return `${this.BASE}/claim-tx?recipient=${recipient}&page=${page}&limit=${limit}`;
  },
};

const routerIface = new ethers.Interface(ABIS.SWAP_ROUTER);
const abi = ethers.AbiCoder.defaultAbiCoder();
function encodeInnerSwap({ tokenIn, tokenOut, recipient, deadlineMs, amountInWei }) {
  const innerParams = abi.encode(
    ['address','address','uint256','address','uint256','uint256','uint256','uint256'],
    [
      tokenIn, tokenOut, 0n, recipient, BigInt(deadlineMs),
      BigInt(amountInWei), 27n, 0n,
    ]
  );
  return '0x1679c792' + innerParams.slice(2);
}
function encodeRouterMulticall(calls) {
  return routerIface.encodeFunctionData('multicall', [calls]);
}

class NeuraBot {
  constructor(cookie, privateKey = null, proxy = null) {
    this.neuraProvider = new ethers.JsonRpcProvider(NEURA_RPC);
    this.sepoliaProvider = new ethers.JsonRpcProvider(SEPOLIA_RPC);

    this.cookie = cookie;
    this.privateKey = privateKey;
    this.wallet = null;
    this.neuraWallet = null;
    this.sepoliaWallet = null;
    this.address = null;

    if (privateKey) {
      try {
        this.wallet = new ethers.Wallet(privateKey);
        this.neuraWallet = this.wallet.connect(this.neuraProvider);
        this.sepoliaWallet = this.wallet.connect(this.sepoliaProvider);
        this.address = this.wallet.address;
      } catch (e) {
        logger.error(`Failed to load private key: ${e.message}. On-chain functions will fail.`);
        this.privateKey = null;
      }
    } else {
      logger.warn('No private key provided. Only API tasks (claim, chat, pulses) will run. Swap/Bridge/Faucet will fail.');
    }

    let agent = null;
    if (proxy) {
      try {
        const fmt = formatProxy(proxy); new URL(fmt);
        agent = new HttpsProxyAgent(fmt);
        logger.info(`Using proxy...`);
      } catch { logger.warn(`Invalid proxy: ${proxy}. Running direct.`); }
    }
    this.api = axios.create({ httpsAgent: agent, httpAgent: agent });
    this.api.defaults.headers.common['User-Agent'] = getUA();
  }

  async executeWithRetry(fn, maxRetries = 3) {
    for (let i = 0; i < maxRetries; i++) {
      try { return await fn(); }
      catch (e) {
        const message = e.message || 'An unknown error occurred.';
        logger.warn(`Attempt ${i + 1}/${maxRetries} failed: ${message}`);
        if (i === maxRetries - 1) {
          throw e; 
        }
        await delay(5000);
      }
    }
  }
  
  async login() {
    logger.step(`Logging in using cookie...`);
    try {
      const idTokenMatch = this.cookie.match(/privy-id-token=([^;]+)/);
      if (!idTokenMatch || !idTokenMatch[1]) {
        throw new Error("Invalid cookie. Could not find 'privy-id-token'.");
      }
      const idToken = idTokenMatch[1];
      
      this.api.defaults.headers.common['Authorization'] = `Bearer ${idToken}`;
      this.api.defaults.headers.common['Cookie'] = this.cookie;
      this.api.defaults.headers.common['Origin'] = 'https://neuraverse.neuraprotocol.io';
      this.api.defaults.headers.common['Referer'] = 'https://neuraverse.neuraprotocol.io/';

      const accResponse = await this.api.get(API_ENDPOINTS.ACCOUNT);
      const addressFromApi = accResponse.data?.address;

      if (!addressFromApi) {
        throw new Error('Cookie is valid, but failed to fetch account data.');
      }

      if (this.address) {
        if (this.address.toLowerCase() !== addressFromApi.toLowerCase()) {
          logger.error(`!!! MISMATCH WARNING !!!`);
          logger.error(`This cookie is for account: ${addressFromApi}`);
          logger.error(`This private key is for: ${this.address}`);
          logger.error(`On-chain functions (swap/bridge) will FAIL!`);
          throw new Error('Account Mismatch: Cookie vs Private Key.');
        }
        logger.success(`Login successful & PK matched: ${this.address.slice(0, 10)}...`);
      } else {
        this.address = addressFromApi;
        logger.success(`API login successful for: ${this.address.slice(0, 10)}... (No PK)`);
      }
    } catch (e) {
      logger.error(`Login failed: ${e.response ? JSON.stringify(e.response.data) : e.message}`);
      throw e;
    }
  }

  async visitSections() {
    logger.step('Visiting all sections (triggers events)...');
    const sections = ['faucet:visit', 'bridge:visit', 'swap:visit'];
    for (const sectionType of sections) {
      try {
        await this.api.post(API_ENDPOINTS.EVENTS, { type: sectionType });
        logger.success(`Visit event sent: ${sectionType}`);
        await delay(1000);
      } catch (e) {
        logger.warn(`Failed to send event ${sectionType}: ${e.message}`);
      }
    }
  }

  async claimFaucet() {
    if (!this.wallet) {
      throw new Error('Private key is required for Faucet. This account was loaded without a PK.');
    }
    logger.step(`Claiming from Faucet for ${this.address}...`);
    try {
      if (!this.api.defaults.headers.common['Authorization']) {
        throw new Error('Authorization token missing. login() must complete successfully.');
      }
      logger.info('Performing pre-flight GraphQL query...');
      const gqlEndpoint = "https://http-testnet-graph-eth.infra.neuraprotocol.io/subgraphs/name/test-eth";
      const gqlQuery = `
        query GetUserTransactions($userAddress: String!, $first: Int, $skip: Int) {
          deposits: tokensDepositeds(
            where: { from: $userAddress }
            first: $first
            skip: $skip
            orderBy: blockTimestamp
            orderDirection: desc
          ) { id }
          claims: tokensClaimeds(
            where: { recipient: $userAddress }
            first: $first
            skip: $skip
            orderBy: blockTimestamp
            orderDirection: desc
          ) { id }
        }`;
      await this.api.post(gqlEndpoint, {
        query: gqlQuery,
        variables: { userAddress: this.address.toLowerCase(), first: 10, skip: 0 },
        operationName: "GetUserTransactions"
      }, {
        headers: {
          'accept': 'application/graphql-response+json, application/json',
          'content-type': 'application/json'
        }
      });
      logger.success('GraphQL query successful.');
      await delay(1200);

      const faucetHeaders = {
        'accept': '*/*',
        'content-type': 'application/json',
      };
      const body = {
        address: this.address,
        userLoggedIn: true,
        chainId: SEPOLIA_CHAIN_ID
      };
      const faucet = await this.api.post(API_ENDPOINTS.FAUCET, body, { headers: faucetHeaders });

      if (faucet.data?.status === 'success' && faucet.data?.data?.transactionHash) {
        const txHash = faucet.data.data.transactionHash;
        logger.success(`Faucet claim successful! Tx: ${txHash}`);
        await this.api.post(API_ENDPOINTS.EVENTS, { type: 'faucet:claimTokens' });
        return txHash;
      } else {
        const message = faucet.data?.message || JSON.stringify(faucet.data);
        throw new Error(`Faucet API returned non-success status: ${message}`);
      }
    } catch (e) {
      const status = e?.response?.status;
      const payload = e?.response?.data ? JSON.stringify(e.response.data) : e.message;
      logger.error(`Faucet claim failed`);
      if (status) logger.error(`[✗] Received Status Code: ${status}`);
      throw e;
    }
  }

  async checkBalances() {
    if (!this.wallet) {
      logger.warn('No private key, cannot check on-chain balances.');
      return;
    }
    logger.step(`Checking balances for ${this.address.slice(0,10)}...`);
    try {
      const neuraBal = await this.neuraProvider.getBalance(this.address);
      logger.info(`Neura Balance  : ${ethers.formatEther(neuraBal)} ANKR`);
      const sepEthBal = await this.sepoliaProvider.getBalance(this.address);
      logger.info(`Sepolia ETH Bal: ${ethers.formatEther(sepEthBal)} ETH`);
      const t = new ethers.Contract(CONTRACTS.SEPOLIA.TANKR, ABIS.ERC20, this.sepoliaProvider);
      const sepBal = await t.balanceOf(this.address);
      logger.info(`Sepolia tANKR  : ${ethers.formatEther(sepBal)} tANKR`);
    } catch { logger.error('Failed to check balances.'); }
  }
    
  async performSwap(tokenIn, tokenOut, amountInStr) {
    if (!this.wallet) {
      throw new Error('Private key is required for Swap. This account was loaded without a PK.');
    }
    logger.step(`Swapping ${amountInStr} ${tokenIn.symbol} → ${tokenOut.symbol}...`);
    try {
        const amountInWei = ethers.parseUnits(amountInStr, tokenIn.decimals);
        const isNativeSwapIn = tokenIn.symbol === 'ANKR';
        if (!isNativeSwapIn) {
            const tokenContract = new ethers.Contract(tokenIn.address, ABIS.ERC20, this.neuraWallet);
            const allowance = await tokenContract.allowance(this.address, CONTRACTS.NEURA.SWAP_ROUTER);
            if (allowance < amountInWei) {
                logger.loading(`Approving ${tokenIn.symbol} for router...`);
                const approveTx = await tokenContract.approve(CONTRACTS.NEURA.SWAP_ROUTER, ethers.MaxUint256);
                const approveRcpt = await approveTx.wait();
                if (approveRcpt.status !== 1) throw new Error('Approve transaction failed');
                logger.success('Approval successful.');
            } else {
                logger.info('Sufficient allowance already exists.');
            }
        }
        const deadlineMs = BigInt(Date.now()) + 20n * 60n * 1000n;
        const tokenInAddressForRouter = isNativeSwapIn ? CONTRACTS.NEURA.WANKR : tokenIn.address;
        const inner = encodeInnerSwap({
          tokenIn: tokenInAddressForRouter,
          tokenOut: tokenOut.address,
          recipient: this.address,
          deadlineMs,
          amountInWei,
        });
        const data = encodeRouterMulticall([inner]);
        const txValue = isNativeSwapIn ? amountInWei : 0n;
        logger.info(`Sending swap transaction...`);
        const tx = await this.neuraWallet.sendTransaction({
          to: CONTRACTS.NEURA.SWAP_ROUTER,
          data,
          value: txValue,
          gasLimit: 600_000, 
        });
        logger.loading(`Swap tx sent. Hash: ${tx.hash}`);
        const rcpt = await tx.wait();
        if (rcpt.status !== 1) throw new Error(`Swap tx reverted on-chain.`);
        logger.success(`Swap successful: ${rcpt.hash}`);
    } catch (e) {
        const msg = e?.shortMessage || e?.message || String(e);
        logger.error(`Swap failed: ${msg}`);
        throw e;
    }
  }
  
  async waitForNeuraBalance(minEth = '0.001', maxAttempts = 15, stepMs = 5000) {
    if (!this.wallet) {
      throw new Error('Private key is required to check balance. This account was loaded without a PK.');
    }
    logger.step(`Waiting for native ANKR balance on Neura to be at least ${minEth} ANKR...`);
    const minWei = ethers.parseEther(minEth);
    for (let i=0;i<maxAttempts;i++){
      const bal = await this.neuraProvider.getBalance(this.address);
      logger.info(`Attempt ${i+1}/${maxAttempts}: Current Neura balance is ${ethers.formatEther(bal)} ANKR.`);
      if (bal >= minWei) { logger.success('Neura balance is sufficient!'); return true; }
      await delay(stepMs);
    }
    throw new Error(`Timeout: Neura ANKR balance < ${minEth}`);
  }

  async bridgeNeuraToSepolia(amountEth) {
    if (!this.wallet) {
      throw new Error('Private key is required for Bridge. This account was loaded without a PK.');
    }
    logger.step(`Bridging ${amountEth} ANKR from Neura → Sepolia...`);
    try {
      const amount = ethers.parseEther(amountEth);
      const bridge = new ethers.Contract(CONTRACTS.NEURA.BRIDGE, ABIS.NEURA_BRIDGE, this.neuraWallet);
      const tx = await bridge.deposit(this.address, SEPOLIA_CHAIN_ID, { value: amount });
      logger.loading(`Bridge deposit tx (Neura): ${tx.hash}`);
      await tx.wait();
      logger.success(`Bridge deposit confirmed.`);
    } catch (e) {
      logger.error(`Bridge Neura→Sepolia failed: ${e?.message || String(e)}`);
      throw e;
    }
  }

  async bridgeSepoliaToNeura(amountEth) {
    if (!this.wallet) {
      throw new Error('Private key is required for Bridge. This account was loaded without a PK.');
    }
    logger.step(`Bridging ${amountEth} tANKR from Sepolia → Neura...`);
    try {
      const amount = ethers.parseEther(amountEth);
      const token = new ethers.Contract(CONTRACTS.SEPOLIA.TANKR, ABIS.ERC20, this.sepoliaWallet);
      const bridge = new ethers.Contract(CONTRACTS.SEPOLIA.BRIDGE, ABIS.SEPOLIA_BRIDGE, this.sepoliaWallet);
      const allowance = await token.allowance(this.address, CONTRACTS.SEPOLIA.BRIDGE);
      if (allowance < amount) {
        logger.loading('Approving bridge to spend tANKR...');
        const approveTx = await token.approve(CONTRACTS.SEPOLIA.BRIDGE, ethers.MaxUint256);
        await approveTx.wait();
        logger.success(`Approve OK.`);
      } else {
        logger.info('Sufficient allowance already set.');
      }
      logger.loading('Depositing tANKR to bridge (Sepolia)...');
      const depTx = await bridge.deposit(amount, this.address);
      await depTx.wait();
      logger.success(`Bridge deposit (Sepolia) OK.`);
    } catch (e) {
      logger.error(`Bridge Sepolia→Neura failed: ${e?.message || String(e)}`);
      throw e;
    }
  }

  async claimValidatedOnSepolia({ waitMs = 60_000, page = 1, limit = 20 } = {}) {
    if (!this.wallet) {
      throw new Error('Private key is required for Bridge Claim. This account was loaded without a PK.');
    }
    logger.step(`Auto-claim Pending Bridge Tx ...`);
    await delay(waitMs);
    try {
      const url = API_ENDPOINTS.claimList(this.address.toLowerCase(), page, limit);
      logger.info(`Fetching claim list: ${url}`);
      const resp = await this.api.get(url);
      const items = resp.data?.transactions || [];
      if (!items.length) {
        logger.info('There are no transactions to claim.');
        return;
      }
      const toClaim = items.filter(
        (x) =>
          String(x.chainId) === String(SEPOLIA_CHAIN_ID) && 
          x.status === 'validated' &&                        
          !!x.encodedMessage && Array.isArray(x.messageSignatures) && x.messageSignatures.length > 0
      );
      if (!toClaim.length) {
        logger.info('There are no validated transactions to claim (the rest have already been claimed).');
        return;
      }
      logger.info(`Found ${toClaim.length} tx validated → Claim on Sepolia...`);
      const bridgeClaim = new ethers.Contract(CONTRACTS.SEPOLIA.BRIDGE, ABIS.BRIDGE_CLAIM, this.sepoliaWallet);
      for (const txinfo of toClaim) {
        const short = `${txinfo.transactionHash?.slice(0,10) || txinfo.id?.slice(0,10) || '0x...'}`;
        try {
          logger.loading(`Claiming ${short} ...`);
          const claimTx = await bridgeClaim.claim(txinfo.encodedMessage, txinfo.messageSignatures);
          const rcpt = await claimTx.wait();
          if (rcpt.status !== 1) throw new Error('Claim tx reverted');
          logger.success(`Claim OK: ${rcpt.hash}`);
        } catch (e) {
          const msg = e?.info?.error?.message || e?.shortMessage || e?.message || String(e);
          if (/already\s*claimed|already\s*processed|duplicate|revert/i.test(msg)) {
            logger.warn(`Skip (Already claimed): ${short}`);
            continue;
          }
          logger.error(`Failed to claim ${short}: ${msg}`);
s        }
      }
    } catch (e) {
      logger.error(`Failed to fetch/execute claim list: ${e?.message || String(e)}`);
    }
  }
  
  async collectPulses() {
    logger.step('Collecting all available Pulses...');
    try {
        const acc = await this.api.get(API_ENDPOINTS.ACCOUNT);
        const pulses = acc.data.pulses.data || [];
        const todo = pulses.filter(p => !p.isCollected);

        if (!todo.length) {
            logger.info('All pulses have already been collected today.');
            return;
        }

        logger.info(`Found ${todo.length} uncollected pulses to claim.`);
        for (const p of todo) {
            try {
                await this.api.post(API_ENDPOINTS.EVENTS, { type: 'pulse:collectPulse', payload: { id: p.id } });
                logger.success(`Collected pulse: ${p.id}.`);
                await delay(1500);
            } catch (e) {
                logger.warn(`Could not claim pulse ${p.id}: ${e.message}`);
            }
        }
        logger.success('All available pulses have been processed.');
    } catch (e) {
        logger.error(`Failed during the pulse collection process: ${e.message}`);
        throw e;
    }
  }

  async chatWithAgent() {
    logger.step('Chatting with a random Agent...');
    try {
      const v = await this.api.get(API_ENDPOINTS.VALIDATORS);
      const list = v.data.validators || [];
      if (!list.length) { logger.warn('No validators found to chat with.'); return; }
      const pick = list[Math.floor(Math.random() * list.length)];
      const payload = { messages: [ { role: 'user', content: 'hello' } ] };
      const resp = await this.api.post(`${API_ENDPOINTS.CHAT}${pick.id}`, payload);
      const reply = resp.data.messages?.[0]?.content || '';
      logger.success(`Agent replied: "${reply.substring(0, 50)}..."`);
    } catch (e) { logger.error(`Chat failed: ${e.message}`); throw e; }
  }

  async claimTasks({ specificTaskId = null } = {}) {
    const taskNameToLog = specificTaskId ? `task "${specificTaskId}"` : 'all claimable tasks';
    logger.step(`Checking and claiming ${taskNameToLog}...`);
    try {
        const tasks = await this.api.get(API_ENDPOINTS.TASKS);
        const allTasks = tasks.data.tasks || [];

        let claimable;
        if (specificTaskId) {
            claimable = allTasks.filter(t => t.id === specificTaskId && t.status === 'claimable');
            if (!claimable.length) {
                const specificTask = allTasks.find(t => t.id === specificTaskId);
                const status = specificTask ? specificTask.status : 'not found';
                logger.info(`Task "${specificTaskId}" is not claimable. Current status: ${status}`);
                return;
            }
        } else {
            claimable = allTasks.filter(t => t.status === 'claimable');
        }

        if (!claimable.length) {
            logger.info('No new tasks to claim.');
            return;
        }

        logger.info(`Found ${claimable.length} claimable tasks.`);
        for (const t of claimable) {
            if (t.source === 'social' || t.source === 'telegram') {
              logger.warn(`Skipping social task: "${t.name}". Please complete manually.`);
              continue;
            }
            await this.api.post(API_ENDPOINTS.taskClaim(t.id));
            logger.success(`Claimed: "${t.name}" (+${t.points} pts)`);
            await delay(1500);
        }
    } catch (e) {
        logger.error(`Failed to claim tasks: ${e.message}`);
        throw e;
    }
  }
}

function loadAccountsFromEnv() {
  const accounts = [];
  const envKeys = Object.keys(process.env);
  const cookieKeys = envKeys.filter(k => k.startsWith('COOKIE_'));

  logger.info(`Found ${cookieKeys.length} cookie(s) in .env file.`);

  for (const cookieKey of cookieKeys) {
    const index = cookieKey.split('_')[1];
    const cookieValue = process.env[cookieKey];
    const pkKey = `PRIVATE_KEY_${index}`;
    const pkValue = process.env[pkKey] || null;

    if (!cookieValue) {
      logger.warn(`Skipping ${cookieKey} because it is empty.`);
      continue;
    }
    
    if (!pkValue) {
      logger.warn(`Cookie ${cookieKey} found, but ${pkKey} not found. On-chain tasks will be skipped for this account.`);
    }

    accounts.push({
      id: index,
      cookie: cookieValue,
      privateKey: pkValue,
    });
  }
  return accounts;
}


async function main() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const proxies = fs.existsSync('proxies.txt') ? fs.readFileSync('proxies.txt','utf-8').split('\n').filter(Boolean) : [];
  
  logger.banner();
  proxies.length ? logger.info(`Loaded ${proxies.length} proxies.\n`) : logger.warn('No proxies loaded. Running in direct mode.\n');

  const accounts = loadAccountsFromEnv();
  if (!accounts.length) {
    logger.error('No accounts found in .env file. Ensure format is COOKIE_1=... / PRIVATE_KEY_1=...');
    rl.close();
    return;
  }

  global.proxies = proxies;

  while (true) {
    const choice = await ask(rl, `
Choose a task to run on ${accounts.length} account(s):
1. All Tasks (Api + On-Chain)
2. Faucet (On-Chain)
3. Swap (On-Chain)
4. Bridge (On-Chain)
5. Claim All Tasks & Pulses Only (API Only)
6. Run Daily Loop (Faucet, Swaps, API Tasks)
7. Exit

Enter number: `);
    
    let tokens = [];
    if (['1', '3', '6'].includes(choice)) {
      tokens = await fetchAvailableTokens();
    }

    if (choice === '1') {
      const bridgeSepoliaToNeuraAmount = await ask(rl, 'Amount to bridge Sepolia→Neura (0 to skip): ');
      const bridgeNeuraToSepoliaAmount = await ask(rl, 'Amount to bridge Neura→Sepolia (0 to skip): ');
      const swapAmountZtusd = await ask(rl, 'Amount of ZTUSD to swap to MOLLY (0 to skip): ');
      const ztUSDToken = tokens.find(t => t.symbol.toUpperCase() === 'ZTUSD');
      const mollyToken = tokens.find(t => t.symbol.toUpperCase() === 'MOLLY');
      if ((!ztUSDToken || !mollyToken) && parseFloat(swapAmountZtusd) > 0) {
        logger.warn('Could not find ZTUSD or MOLLY. Swap step will be skipped.');
      }

      for (const account of accounts) {
        const proxy = proxies.length ? proxies[Math.floor(Math.random() * proxies.length)] : null;
        const bot = new NeuraBot(account.cookie, account.privateKey, proxy);
        logger.step(`--- Processing Account ${account.id} (Address: ${bot.address || '...'}) ---`);
        try {
          await bot.executeWithRetry(() => bot.login());
          await runTaskWithRetries(() => bot.visitSections(), "Visit All Sections");
          await delay(2000);
          await runTaskWithRetries(() => bot.claimTasks(), "Claim Initial Tasks");
          await delay(3000);

          if (bot.privateKey) {
            if (parseFloat(swapAmountZtusd) > 0 && ztUSDToken && mollyToken) {
              await runTaskWithRetries(async () => {
                await bot.performSwap(ztUSDToken, mollyToken, swapAmountZtusd);
                logger.loading('Waiting 5s before swapping back...');
                await delay(5000);
                const mollyCtr = new ethers.Contract(mollyToken.address, ABIS.ERC20, bot.neuraWallet);
                const balMolly = await mollyCtr.balanceOf(bot.address);
                if (balMolly > 0n) {
                  const mollyAmountStr = ethers.formatUnits(balMolly, mollyToken.decimals);
                  await bot.performSwap(mollyToken, ztUSDToken, mollyAmountStr);
                } else {
                  logger.warn('No MOLLY balance to swap back.');
                }
              }, `Swap ${swapAmountZtusd} ZTUSD ↔ MOLLY`);
              await delay(3000);
            }

            if (parseFloat(bridgeSepoliaToNeuraAmount) > 0) {
              await runTaskWithRetries(() => bot.bridgeSepoliaToNeura(bridgeSepoliaToNeuraAmount), "Bridge Sepolia to Neura");
              await delay(3000);
            }
            if (parseFloat(bridgeNeuraToSepoliaAmount) > 0) {
              await runTaskWithRetries(async () => {
                await bot.waitForNeuraBalance(bridgeNeuraToSepoliaAmount);
                await bot.bridgeNeuraToSepolia(bridgeNeuraToSepoliaAmount);
              }, "Bridge Neura to Sepolia");
              await delay(3000);
            }
            await runTaskWithRetries(() => bot.claimFaucet(), 'Claim Faucet');
            await delay(3000);
          	await runTaskWithRetries(() => bot.claimValidatedOnSepolia({ waitMs: 0 }), 'Claim Pending Bridge');
            await delay(3000);
          }
          
          await runTaskWithRetries(() => bot.collectPulses(), 'Collect All Pulses');
          await delay(3000);
          await runTaskWithRetries(() => bot.chatWithAgent(), 'Chat with Agent');
          await delay(3000);
          
          logger.step('Attempting to claim all completed tasks...');
          await runTaskWithRetries(() => bot.claimTasks(), "Claim All Completed Tasks");
          await bot.checkBalances();
        } catch (e) {
          logger.error(`Critical error on Account ${account.id}: ${e.message}`);
        }
      }
      continue;
    }

    if (choice === '2') {
      for (const account of accounts) {
        const proxy = proxies.length ? proxies[Math.floor(Math.random() * proxies.length)] : null;
        const bot = new NeuraBot(account.cookie, account.privateKey, proxy);
        logger.step(`--- Processing Account ${account.id} (Faucet) ---`);
        try {
          await bot.executeWithRetry(() => bot.login());
          await runTaskWithRetries(() => bot.visitSections(), "Visit All Sections");
          await runTaskWithRetries(() => bot.claimFaucet(), 'Claim Faucet');
          await delay(2000);
          await runTaskWithRetries(() => bot.claimTasks(), "Claim Faucet Task");
        } catch(e) { logger.error(`Faucet flow failed: ${e.message}`); }
      }
      continue;
    }

    if (choice === '3') {
      if (!tokens.length) { logger.error("Tokens not loaded"); continue; }
      console.log('\nAvailable Tokens:');
      tokens.forEach((t, i) => console.log(`${i + 1}. ${t.symbol}`));
      const fromIndexStr = await ask(rl, '\nEnter FROM token number: ');
      const toIndexStr = await ask(rl, 'Enter TO token number: ');
      const fromIndex = parseInt(fromIndexStr, 10) - 1;
      const toIndex = parseInt(toIndexStr, 10) - 1;

      if (isNaN(fromIndex) || isNaN(toIndex) || !tokens[fromIndex] || !tokens[toIndex] || fromIndex === toIndex) {
          logger.error('Invalid token selection.'); continue;
      }
      const tokenA = tokens[fromIndex];
      const tokenB = tokens[toIndex];
      const amountAStr = await ask(rl, `Enter amount of ${tokenA.symbol} to swap: `);
     const repeatStr = await ask(rl, 'How many times to swap back and forth? (e.g., 1) ');
      const repeats = parseInt(repeatStr, 10) || 1;

      for (const account of accounts) {
        const proxy = proxies.length ? proxies[Math.floor(Math.random() * proxies.length)] : null;
        const bot = new NeuraBot(account.cookie, account.privateKey, proxy);
        logger.step(`--- Processing Account ${account.id} (Swap) ---`);
        try {
          await bot.executeWithRetry(() => bot.login());
          for (let j = 0; j < repeats; j++) {
            logger.step(`--- Swap Cycle ${j+1}/${repeats} ---`);
            await bot.performSwap(tokenA, tokenB, amountAStr);
            logger.loading('Waiting 5s before swapping back...');
            await delay(5000);
            
            let amountBStrToSwap;
            if (tokenB.symbol === 'ANKR') {
              const balanceWei = await bot.neuraProvider.getBalance(bot.address);
              const gasReserve = ethers.parseEther('0.1'); 
              if (balanceWei > gasReserve) amountBStrToSwap = ethers.formatEther(balanceWei - gasReserve);
         } else {
              const tokenBContract = new ethers.Contract(tokenB.address, ABIS.ERC20, bot.neuraWallet);
              const tokenBBalance = await tokenBContract.balanceOf(bot.address);
              if (tokenBBalance > 0n) amountBStrToSwap = ethers.formatUnits(tokenBBalance, tokenB.decimals);
            }
            if (amountBStrToSwap) await bot.performSwap(tokenB, tokenA, amountBStrToSwap);
            else logger.warn(`No ${tokenB.symbol} balance to swap back.`);
            await delay(5000);
          }
          await runTaskWithRetries(() => bot.claimTasks(), "Claim Swap Tasks");
        } catch (e) { logger.error(`Swap flow failed: ${e.message}`); }
      }
      continue;
    }

  	if (choice === '4' || choice === '5') {
      let bridgeSepoliaToNeuraAmount = '0';
      let bridgeNeuraToSepoliaAmount = '0';
      if (choice === '4') {
        bridgeSepoliaToNeuraAmount = await ask(rl, 'Amount to bridge Sepolia→Neura (0 to skip): ');
        bridgeNeuraToSepoliaAmount = await ask(rl, 'Amount to bridge Neura→Sepolia (0 to skip): ');
      }

      for (const account of accounts) {
        const proxy = proxies.length ? proxies[Math.floor(Math.random() * proxies.length)] : null;
        const bot = new NeuraBot(account.cookie, account.privateKey, proxy);
        const taskName = choice === '4' ? 'Bridge' : 'API Tasks';
        logger.step(`--- Processing Account ${account.id} (${taskName}) ---`);
        try {
          await bot.executeWithRetry(() => bot.login());
          
          if(choice === '5') {
            await runTaskWithRetries(() => bot.collectPulses(), "Collect All Pulses");
            await delay(2000);
            await runTaskWithRetries(() => bot.claimTasks(), "Claim All Available Tasks");
          }
          
          if (choice === '4') {
            if (parseFloat(bridgeSepoliaToNeuraAmount) > 0) await runTaskWithRetries(() => bot.bridgeSepoliaToNeura(bridgeSepoliaToNeuraAmount), "Bridge Sepolia to Neura");
          	if (parseFloat(bridgeNeuraToSepoliaAmount) > 0) {
              await runTaskWithRetries(async () => {
                await bot.waitForNeuraBalance(bridgeNeuraToSepoliaAmount);
              	await bot.bridgeNeuraToSepolia(bridgeNeuraToSepoliaAmount);
              }, "Bridge Neura to Sepolia");
          	}
          }
          await bot.checkBalances();
        } catch (e) { logger.error(`Flow failed: ${e.message}`); }
      }
      continue;
    }

    if (choice === '6') {
        const ankrToken = tokens.find(t => t.symbol.toUpperCase() === 'ANKR');
        const ztusdToken = tokens.find(t => t.symbol.toUpperCase() === 'ZTUSD');

        if (!ankrToken || !ztusdToken) {
            logger.error('Could not find ANKR or ZTUSD tokens. Cannot perform daily swaps.');
            continue;
        }

        while (true) { 
            logger.step('--- STARTING NEW DAILY RUN ---');
            for (const account of accounts) {
                const proxy = proxies.length ? proxies[Math.floor(Math.random() * proxies.length)] : null;
                const bot = new NeuraBot(account.cookie, account.privateKey, proxy);
                logger.step(`--- Processing Account ${account.id} (Address: ${bot.address || '...'}) ---`);
                
                try {
                    await bot.executeWithRetry(() => bot.login());
                    
                    await runTaskWithRetries(() => bot.visitSections(), "Visit All Sections");
                    await delay(2000);

                    if (bot.privateKey) {
                        await runTaskWithRetries(() => bot.claimFaucet(), "Claim Faucet");
                        await delay(2000);

                        await runTaskWithRetries(
                            () => bot.performSwap(ankrToken, ztusdToken, '0.001'), 
                            "Swap 0.001 ANKR -> ZTUSD"
                        );
                        await delay(2000);

                        await runTaskWithRetries(
                            () => bot.performSwap(ztusdToken, ankrToken, '0.0001'), 
                            "Swap 0.00001 ZTUSD -> ANKR"
                        );
                        await delay(2000);
                    } else {
                         logger.warn(`Skipping on-chain tasks (Faucet, Swap) for Account ${account.id} - No Private Key.`);
                    }

                    await runTaskWithRetries(() => bot.chatWithAgent(), "Chat with Agent");
                    await delay(2000);

                    await runTaskWithRetries(() => bot.collectPulses(), "Collect All Pulses");
                    await delay(2000);

                    await runTaskWithRetries(() => bot.claimTasks(), "Claim All Available Tasks");

                    if (bot.privateKey) {
                        await bot.checkBalances();
                    }

                } catch (e) {
                    logger.error(`Critical error on Account ${account.id}: ${e.message}`);
                }
                logger.success(`--- Finished Account ${account.id} ---`);
            }
            
            logger.success('--- DAILY RUN COMPLETED FOR ALL ACCOUNTS ---');
            
            const DAILY_COOLDOWN_MS = 24 * 60 * 60 * 1000;
            await showCountdown(DAILY_COOLDOWN_MS, 'Waiting for next daily run...');
        
        }
    }

    if (choice === '7') {
      break;
    }

    logger.error('Invalid selection.');
  	await ask(rl, '\nPress Enter to return to the main menu...');
  }
  rl.close();
  logger.success('Bot finished.');
}

main().catch((err) => {
  logger.error(`Critical error occurred: ${err.message}`);
  process.exit(1);
});
