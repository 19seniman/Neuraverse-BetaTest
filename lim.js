const { ethers } = require('ethers');
const axios = require('axios');
const fs = require('fs');
const readline = require('readline');
const dotenv = require('dotenv');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SiweMessage } = require('siwe');

dotenv.config();

const colors = {
  reset: '\x1b[0m', cyan: '\x1b[36m', green: '\x1b[32m', yellow: '\x1b[33m',
  red: '\x1b[31m', white: '\x1b[37m', bold: '\x1b[1m',
  magenta: '\x1b[35m', blue: '\x1b[34m', gray: '\x1b[90m', 
};

const logger = {
    info: (msg) => console.log(`${colors.cyan}[i] ${msg}${colors.reset}`),
    warn: (msg) => console.log(`${colors.yellow}[!] ${msg}${colors.reset}`),
    error: (msg) => console.log(`${colors.red}[x] ${msg}${colors.reset}`),
    success: (msg) => console.log(`${colors.green}[+] ${msg}${colors.reset}`),
    loading: (msg) => console.log(`${colors.magenta}[*] ${msg}${colors.reset}`),
    step: (msg) => console.log(`${colors.blue}[>] ${colors.bold}${msg}${colors.reset}`),
    critical: (msg) => console.log(`${colors.red}${colors.bold}[FATAL] ${msg}${colors.reset}`),
    summary: (msg) => console.log(`${colors.green}${colors.bold}[SUMMARY] ${msg}${colors.reset}`),
    banner: () => {
        const border = `${colors.blue}${colors.bold}╔═════════════════════════════════════════╗${colors.reset}`;
        const title = `${colors.blue}${colors.bold}║   🍉 19Seniman From Insider    🍉   ║${colors.reset}`;
        const bottomBorder = `${colors.blue}${colors.bold}╚═════════════════════════════════════════╝${colors.reset}`;
        
        console.log(`\n${border}`);
        console.log(`${title}`);
        console.log(`${bottomBorder}\n`);
    },
    section: (msg) => {
        const line = '─'.repeat(40);
        console.log(`\n${colors.gray}${line}${colors.reset}`);
        if (msg) console.log(`${colors.white}${colors.bold} ${msg} ${colors.reset}`);
        console.log(`${colors.gray}${line}${colors.reset}\n`);
    },
    countdown: (msg) => process.stdout.write(`\r${colors.blue}[⏰] ${msg}${colors.reset}`),
};

const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const ask = (rl, q) => new Promise((res) => rl.question(q, res));
const getRandomAmount = (min, max) => (Math.random() * (max - min) + min).toFixed(5);
const getUA = () => ([
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
])[Math.floor(Math.random() * 2)];

function formatProxy(p) {
  if (!p || !p.includes('://')) return p;
  const [proto, rest] = p.split('://');
  const atCount = (rest.match(/@/g) || []).length;
  if (atCount !== 1) return p;
  const [a, b] = rest.split('@');
  if (b.includes(':')) return `${proto}://${b}@${a}`;
  return p;
}

function extractPrivyCookies(setCookieHeaders = []) {
  if (!Array.isArray(setCookieHeaders)) return {};
  const wanted = ['privy-token', 'privy-session'];
  const out = {};
  for (const raw of setCookieHeaders) {
    const [kv] = raw.split(';');
    const [k, v] = kv.split('=');
    const name = (k || '').trim();
    const val = (v || '').trim();
    if (wanted.includes(name)) out[name] = val;
  }
  return out;
}

async function fetchAvailableTokens() {
    logger.info('Fetching available swap tokens...');
    try {
        const endpoint = "https://api.goldsky.com/api/public/project_cmc8t6vh6mqlg01w19r2g15a7/subgraphs/analytics/1.0.0/gn";
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
            const message = error?.message || error?.shortMessage || 'An unknown error occurred.';
            logger.warn(`Attempt ${i + 1}/${maxRetries} for task "${taskName}" failed: ${message}`);
            if (i === maxRetries - 1) {
                logger.error(`Task "${taskName}" failed after ${maxRetries} attempts. Moving to the next task.`);
            } else {
                logger.loading('Waiting 5 seconds before next retry...');
                await delay(5000);
            }
        }
    }
}

// Helper function untuk hitungan mundur 24 jam
async function countdownAndDelay(ms) {
    const duration = Math.round(ms / 1000); // seconds
    for (let i = duration; i > 0; i--) {
        const h = Math.floor(i / 3600);
        const m = Math.floor((i % 3600) / 60);
        const s = i % 60;
        const timeString = `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
        logger.countdown(`Next cycle starts in: ${timeString}`);
        await delay(1000);
    }
    process.stdout.write('\n'); // New line after countdown
}


const NEURA_RPC = 'https://testnet.rpc.neuraprotocol.io/';
const SEPOLIA_RPC = 'https://ethereum-sepolia-rpc.publicnode.com/';
const NEURA_CHAIN_ID = 28802;
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
  AUTH_BASE: 'https://privy.neuraverse.neuraprotocol.io/api/v1', 
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
const PRIVY_APP_ID = 'cmbpempz2011ll10l7iucga14';

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
  constructor(privateKey, proxy = null) {
    this.neuraProvider = new ethers.JsonRpcProvider(NEURA_RPC);
    this.sepoliaProvider = new ethers.JsonRpcProvider(SEPOLIA_RPC);
    this.wallet = new ethers.Wallet(privateKey);
    this.neuraWallet = this.wallet.connect(this.neuraProvider);
    this.sepoliaWallet = this.wallet.connect(this.sepoliaProvider);
    this.address = this.wallet.address;

    let agent = null;
    if (proxy) {
      try {
        const fmt = formatProxy(proxy); new URL(fmt);
        agent = new HttpsProxyAgent(fmt);
        logger.info(`Using proxy for wallet ${this.address.slice(0, 10)}...`);
      } catch { logger.warn(`Invalid proxy: ${proxy}. Running direct.`); }
    }
    this.api = axios.create({ httpsAgent: agent, httpAgent: agent });
    this.api.defaults.headers.common['User-Agent'] = getUA();
    this.cookies = '';
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
    logger.step(`Logging in for wallet: ${this.address}`);
    try {
      const h = {
        accept: 'application/json',
        'privy-app-id': PRIVY_APP_ID,
        'privy-ca-id': '1f9fffee-01be-4aba-9c7f-499a39e4c47b',
        'privy-client': 'react-auth:2.25.0',
        'Content-Type': 'application/json',
        Referer: 'https://neuraverse.neuraprotocol.io/',
        Origin: 'https://neuraverse.neuraprotocol.io',
      };

      const init = await this.api.post(API_ENDPOINTS.AUTH_INIT, { address: this.address }, {
        headers: h,
        withCredentials: true,
      });
      const { nonce, issuedAt } = init.data || {};
      if (!nonce) throw new Error('Privy init: nonce missing');

      const siwe = new SiweMessage({
        domain: 'neuraverse.neuraprotocol.io',
        address: this.address,
        statement: 'By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.',
        uri: 'https://neuraverse.neuraprotocol.io',
        version: '1',
        chainId: NEURA_CHAIN_ID,
        nonce,
        issuedAt,
        resources: ['https://privy.io'],
      });
      const msgToSign = siwe.prepareMessage();
      const signature = await this.wallet.signMessage(msgToSign);

      const auth = await this.api.post(
        API_ENDPOINTS.AUTH_AUTHENTICATE,
        {
          message: msgToSign,
          signature,
          chainId: `eip155:${NEURA_CHAIN_ID}`,
          walletClientType: 'metamask',
          connectorType: 'injected',
          mode: 'login-or-sign-up',
        },
        { headers: h, withCredentials: true, }
      );

      this.identityToken = auth.data?.identity_token;
      if (!this.identityToken) throw new Error('Privy authenticate: identity_token missing');

      const setCookie = [].concat(init.headers['set-cookie'] || []).concat(auth.headers['set-cookie'] || []);
      const jar = extractPrivyCookies(setCookie);

      this.cookies =
        `privy-token=${jar['privy-token'] || ''}; ` +
        `privy-session=${jar['privy-session'] || ''}; ` +
        `privy-id-token=${this.identityToken}`;

      this.api.defaults.headers.common['Authorization'] = `Bearer ${this.identityToken}`;
      logger.success('Successfully logged in.');
    } catch (e) {
      logger.error(`Login failed: ${e.response ? JSON.stringify(e.response.data) : e.message}`);
      throw e;
    }
  }

  async claimFaucet() {
    logger.step(`Claiming from Faucet for ${this.address} (authenticated)...`);
    try {
      if (!this.cookies || !/privy-token=/.test(this.cookies) || !/privy-session=/.test(this.cookies) || !/privy-id-token=/.test(this.cookies)) {
        throw new Error('Privy session cookies missing. Make sure login() ran against privy.neuraverse.neuraprotocol.io and captured cookies.');
      }
      if (!this.identityToken) {
        throw new Error('identity_token missing. login() must complete successfully before claiming faucet.');
      }

      try {
        await this.api.get(API_ENDPOINTS.ACCOUNT, {
          headers: {
            'accept': 'application/json',
            'Authorization': `Bearer ${this.identityToken}`,
            'Referer': 'https://neuraverse.neuraprotocol.io/',
            'Origin': 'https://neuraverse.neuraprotocol.io',
            'Cookie': this.cookies,
          }
        });
      } catch (e) {
        logger.warn(`Account check failed (continuing): ${e?.response?.status || ''}`);
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
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'Authorization': `Bearer ${this.identityToken}`,
        'Referer': 'https://neuraverse.neuraprotocol.io/?section=faucet',
        'Origin': 'https://neuraverse.neuraprotocol.io',
        'Cookie': this.cookies, 
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

        await this.api.post(
          API_ENDPOINTS.EVENTS,
          { type: 'faucet:claimTokens' },
          {
            headers: {
              'content-type': 'application/json',
              'Authorization': `Bearer ${this.identityToken}`,
              'Cookie': this.cookies,
              'Referer': 'https://neuraverse.neuraprotocol.io/',
              'Origin': 'https://neuraverse.neuraprotocol.io',
            }
          }
        );

        return txHash;
      } else {
        const message = faucet.data?.message || JSON.stringify(faucet.data);
        throw new Error(`Faucet API returned non-success status: ${message}`);
      }
    } catch (e) {
      const status = e?.response?.status;
      const payload = e?.response?.data ? JSON.stringify(e.response.data) : e.message;
      logger.error(`Faucet claim failed: ${payload}`);
      if (status) logger.error(`[x] Received Status Code: ${status}`); // Used [x] for error consistency
      throw e;
    }
  }

  async checkBalances() {
    logger.step(`Checking balances for ${this.address.slice(0,10)}...`);
    try {
      const neuraBal = await this.neuraProvider.getBalance(this.address);
      logger.info(`Neura Balance  : ${ethers.formatEther(neuraBal)} ANKR`);
      const sepEthBal = await this.sepoliaProvider.getBalance(this.address);
      logger.info(`Sepolia ETH Bal: ${ethers.formatEther(sepEthBal)} ETH`);
      const t = new ethers.Contract(CONTRACTS.SEPOLIA.TANKR, ABIS.ERC20, this.sepoliaProvider);
      const sepBal = await t.balanceOf(this.address);
      logger.info(`Sepolia tANKR  : ${ethers.formatEther(sepBal)} tANKR`);
    } catch { logger.error('Failed to check balances.'); }
  }
    
  async performSwap(tokenIn, tokenOut, amountInStr) {
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
    logger.step(`Waiting for native ANKR balance on Neura to be at least ${minEth} ANKR...`);
    const minWei = ethers.parseEther(minEth);
    for (let i=0;i<maxAttempts;i++){
      const bal = await this.neuraProvider.getBalance(this.address);
      logger.info(`Attempt ${i+1}/${maxAttempts}: Current Neura balance is ${ethers.formatEther(bal)} ANKR.`);
      if (bal >= minWei) { logger.success('Neura balance is sufficient!'); return true; }
      logger.countdown(`Checking in ${Math.round(stepMs / 1000)}s...`); // Use new countdown
      await delay(stepMs);
    }
    throw new Error(`Timeout: Neura ANKR balance < ${minEth}`);
  }

  async bridgeNeuraToSepolia(amountEth) {
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
    logger.step(`Auto-claim Pending Bridge Tx ...`);
    if (waitMs > 0) {
      logger.loading(`Waiting ${Math.round(waitMs / 1000)} seconds for validation...`);
      await delay(waitMs);
    }

    try {
      const url = API_ENDPOINTS.claimList(this.address.toLowerCase(), page, limit);
      logger.info(`Fetching claim list: ${url}`);
      const resp = await this.api.get(url, {
        headers: {
          accept: '*/*',
          'content-type': 'application/json',
          Referer: 'https://neuraverse.neuraprotocol.io/',
        },
      });

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
        }
      }
    } catch (e) {
      logger.error(`Failed to fetch/execute claim list: ${e?.message || String(e)}`);
    }
  }

  async claimPulses() {
    logger.step('Claiming Pulses...');
    try {
      const acc = await this.api.get(API_ENDPOINTS.ACCOUNT);
      const pulses = acc.data.pulses.data || [];
      const todo = pulses.filter(p => !p.isCollected);
      if (!todo.length) { logger.info('All pulses have already been collected today.'); return; }
      logger.info(`Found ${todo.length} uncollected pulses.`);
      for (const p of todo) {
        await this.api.post(API_ENDPOINTS.EVENTS, { type: 'pulse:collectPulse', payload: { id: p.id } });
        logger.success(`Collected ${p.id}.`); await delay(1000);
      }
    } catch (e) { logger.error(`Failed to claim pulses: ${e.message}`); throw e; }
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

  async claimTasks() {
    logger.step('Checking and claiming tasks...');
    try {
      const tasks = await this.api.get(API_ENDPOINTS.TASKS);
      const claimable = (tasks.data.tasks || []).filter(t => t.status === 'claimable');
      if (!claimable.length) { logger.info('No new tasks to claim.'); return; }
      logger.info(`Found ${claimable.length} claimable tasks.`);
      for (const t of claimable) {
        await this.api.post(API_ENDPOINTS.taskClaim(t.id));
        logger.success(`Claimed: "${t.name}" (+${t.points} pts)`);
        await delay(1000);
      }
    } catch (e) { logger.error(`Failed to claim tasks: ${e.message}`); throw e; }
  }
}

async function loadExistingWalletsFlow(
  proxies, 
  bridgeSepoliaToNeuraAmount, 
  bridgeNeuraToSepoliaAmount, 
  swapAmountZtusd, 
  swapRepeats, 
  ztUSDToken, 
  mollyToken
) {
  const pks = Object.keys(process.env).filter(k => k.startsWith('PRIVATE_KEY_')).map(k => process.env[k]).filter(Boolean);
  if (!pks.length) { logger.error('No private keys found in .env file.'); return; }
  logger.info(`Found ${pks.length} wallets in .env file.`);
  
  // Parameter check
  if (parseFloat(swapAmountZtusd) > 0 && swapRepeats > 0 && (!ztUSDToken || !mollyToken)) {
    logger.warn('Could not find ZTUSD or MOLLY in token list. Swap step will be skipped for this cycle.');
  }

  const wallets = Object.keys(process.env)
    .filter(k => k.startsWith('PRIVATE_KEY_'))
    .map(k => process.env[k])
    .filter(Boolean);
  
  for (let idx = 0; idx < wallets.length; idx++) {
    const proxy = (proxies || []).length
      ? proxies[Math.floor(Math.random() * proxies.length)]
      : undefined;

    const pk = wallets[idx];
    const bot = new NeuraBot(pk, proxy);
    logger.section(`[Wallet ${idx+1}/${wallets.length}] ${bot.address.slice(0,10)}... (proxy ${proxy ? 'ON' : 'OFF'})`);

    try {
      await bot.executeWithRetry(() => bot.login());
      await bot.checkBalances();
      
      const tasks = [];

      // 1. Faucet (Sepolia)
      tasks.push({ name: 'Claim Faucet', fn: () => bot.claimFaucet() });
      tasks.push({ name: 'Check Balances After Faucet', fn: () => bot.checkBalances() });

      // 2. Claim Pending Bridge (Sepolia -> Neura)
      tasks.push({ name: 'Claim Pending Bridge (Sepolia→Neura)', fn: () => bot.claimValidatedOnSepolia({ waitMs: 0 }) });
      
      // 3. Bridge (Sepolia -> Neura) - MOVED UP UNTUK MENDAPATKAN ANKR GAS SEBELUM SWAP
      if (parseFloat(bridgeSepoliaToNeuraAmount) > 0) {
        tasks.push({ 
          name: `Bridge Sepolia to Neura (${bridgeSepoliaToNeuraAmount} tANKR)`, 
          fn: async () => {
            await bot.bridgeSepoliaToNeura(bridgeSepoliaToNeuraAmount);
            logger.loading('Waiting 30 seconds for funds to arrive on Neura for gas...');
            await delay(30000); // Tunda untuk memastikan dana tiba
          }
        });
        tasks.push({ name: 'Check Balances After Bridge', fn: () => bot.checkBalances() });
      } else {
        logger.warn('Skipping Sepolia → Neura Bridge: Amount is 0 or invalid. Ensure you have ANKR gas on Neura for the swap.');
      }

      // 4. Swap (ZTUSD <-> MOLLY)
      const canSwap = parseFloat(swapAmountZtusd) > 0 && swapRepeats > 0 && ztUSDToken && mollyToken;
      if (canSwap) {
        for(let j = 0; j < swapRepeats; j++) {
            tasks.push({
                name: `[Swap Cycle ${j+1}/${swapRepeats}] ZTUSD → MOLLY`,
                fn: async () => {
                  
                  await bot.performSwap(ztUSDToken, mollyToken, swapAmountZtusd);

                  logger.loading('Waiting 5 seconds before reverse swap...');
                  await delay(5000);

                  const mollyCtr = new ethers.Contract(mollyToken.address, ABIS.ERC20, bot.neuraWallet);
                  const balMolly = await mollyCtr.balanceOf(bot.address);
                  if (balMolly > 0n) {
                    const mollyAmountStr = ethers.formatUnits(balMolly, mollyToken.decimals);
                    await bot.performSwap(mollyToken, ztUSDToken, mollyAmountStr);
                  } else {
                    logger.warn('No MOLLY balance detected for reverse swap. Skipping.');
                  }
                }
            });
        }
      }
      
      // 5. Bridge (Neura -> Sepolia)
      if (parseFloat(bridgeNeuraToSepoliaAmount) > 0) {
        tasks.push({
          name: `Bridge Neura to Sepolia (${bridgeNeuraToSepoliaAmount} ANKR)`,
          fn: async () => {
            await bot.waitForNeuraBalance(bridgeNeuraToSepoliaAmount);
            await bot.bridgeNeuraToSepolia(bridgeNeuraToSepoliaAmount);
          }
        });
      }

      // 6. Claim Tasks & Pulses
      tasks.push({ name: 'Claim Pulses', fn: () => bot.claimPulses() });
      tasks.push({ name: 'Chat with Agent', fn: () => bot.chatWithAgent() });
      tasks.push({ name: 'Claim Tasks', fn: () => bot.claimTasks() });
      
      // 7. Final Balance Check
      tasks.push({ name: 'Final Balance Check', fn: () => bot.checkBalances() });

      logger.info(`Starting automatic sequence of ${tasks.length} tasks...`);
      for (const task of tasks) {
        await runTaskWithRetries(task.fn, task.name);
        logger.loading('Cooling down 5 seconds before next step...');
        await delay(5000);
      }

    } catch (e) {
      logger.critical(`A critical error occurred for wallet ${bot.address}. Moving to next wallet. Error: ${e.message}`);
    }
  }
  return;
}

async function main() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const proxies = fs.existsSync('proxies.txt') ? fs.readFileSync('proxies.txt','utf-8').split('\n').filter(Boolean) : [];
  
  logger.banner();
  proxies.length ? logger.info(`Loaded ${proxies.length} proxies.\n`) : logger.warn('No proxies loaded. Running in direct mode.\n');
  
  // --- PENGATURAN PARAMETER AWAL (DILAKUKAN SEKALI) ---
  logger.section('PENGATURAN PARAMETER OTOMATIS');
  const bridgeSepoliaToNeuraAmount = await ask(rl, 'Amount to bridge Sepolia→Neura (enter 0 to skip): ');
  const bridgeNeuraToSepoliaAmount = await ask(rl, 'Amount to bridge Neura→Sepolia (enter 0 to skip): ');
  const swapAmountZtusd = await ask(rl, 'Amount of ZTUSD to swap to MOLLY (enter 0 to skip): ');
  const swapRepeatStr = await ask(rl, 'How many times to perform ZTUSD ↔️ MOLLY swap? (e.g., 1): ');
  const swapRepeats = parseInt(swapRepeatStr, 10) || 0;
  
  const tokens = await fetchAvailableTokens();
  const ztUSDToken = tokens.find(t => t.symbol.toUpperCase() === 'ZTUSD');
  const mollyToken = tokens.find(t => t.symbol.toUpperCase() === 'MOLLY');
  
  if (parseFloat(swapAmountZtusd) > 0 && swapRepeats > 0 && (!ztUSDToken || !mollyToken)) {
    logger.error('Could not find ZTUSD or MOLLY in token list. Please fix the token list or set swap amount to 0.');
    rl.close();
    return;
  }
  
  rl.close(); // Tutup RL karena input dari user sudah selesai

  // --- AUTOMATION LOOP 24 JAM ---
  const DELAY_DURATION = 24 * 60 * 60 * 1000; // 24 jam dalam ms

  while (true) {
    const cycleStartTime = Date.now();
    logger.section(`STARTING NEW AUTOMATED CYCLE: ${new Date().toLocaleString()}`);
    
    await loadExistingWalletsFlow(
      proxies,
      bridgeSepoliaToNeuraAmount,
      bridgeNeuraToSepoliaAmount,
      swapAmountZtusd,
      swapRepeats,
      ztUSDToken,
      mollyToken
    );
    
    const elapsed = Date.now() - cycleStartTime;
    const waitTime = DELAY_DURATION - elapsed;
    
    if (waitTime > 0) {
      logger.section(`CYCLE COMPLETE. WAITING 24 HOURS UNTIL NEXT RUN.`);
      await countdownAndDelay(waitTime);
    } else {
      logger.warn('Previous cycle took longer than 24 hours. Starting next cycle immediately.');
    }
  }
  // Tidak perlu ada rl.close() di sini karena loop berjalan terus
}

main().catch((err) => {
  logger.critical(`A critical error occurred: ${err.message}`); // Use new critical logger
  process.exit(1);
});
