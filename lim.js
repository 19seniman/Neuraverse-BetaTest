const { ethers } = require('ethers');
const axios = require('axios');
const fs = require('fs');
const readline = require('readline');
const dotenv = require('dotenv');
const { HttpsProxyAgent } = require('https-proxy-agent');

dotenv.config();

const colors = {
    reset: '\x1b[0m',
    cyan: '\x1b[36m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    white: '\x1b[37m',
    bold: '\x1b[1m',
    magenta: '\x1b[35m',
    blue: '\x1b[34m',
    gray: '\x1b[90m',
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
// --- END NEW LOGGER DEFINITION ---


// --- CONFIGURATION ---
const RPC_URL = process.env.RPC_URL || "https://rpc.dev-us-west1.pulsechain.com";
const API_BASE_URL = process.env.API_BASE_URL || "https://api.dev-us-west1.pulsechain.com";
const FAUCET_API_URL = `${API_BASE_URL}/faucet`;
const SWAP_API_URL = `${API_BASE_URL}/swap`;
const CLAIM_API_URL = `${API_BASE_URL}/tasks/claim`;
const COLLECT_PULSES_API_URL = `${API_BASE_URL}/pulses/collect`;
const CHAT_API_URL = `${API_BASE_URL}/chat`;
const WALLET_FILE = 'wallets.json';
const MAX_RETRIES = 3;

// --- UTILITIES ---

/**
 * Delays execution for a given number of milliseconds.
 * @param {number} ms - The number of milliseconds to wait.
 */
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Prompts the user for input.
 * @param {readline.Interface} rl - The readline interface.
 * @param {string} question - The question to ask.
 * @returns {Promise<string>} The user's input.
 */
const ask = (rl, question) => {
    return new Promise(resolve => {
        rl.question(question, (answer) => {
            resolve(answer);
        });
    });
};

/**
 * Loads accounts from the JSON file.
 * @returns {Array<Object>} List of account objects.
 */
const loadAccounts = () => {
    try {
        if (fs.existsSync(WALLET_FILE)) {
            const data = fs.readFileSync(WALLET_FILE, 'utf8');
            return JSON.parse(data);
        }
        return [];
    } catch (e) {
        logger.error(`Error loading accounts: ${e.message}`);
        return [];
    }
};

/**
 * Saves the current list of accounts to the JSON file.
 * @param {Array<Object>} accounts - List of account objects to save.
 */
const saveAccounts = (accounts) => {
    try {
        fs.writeFileSync(WALLET_FILE, JSON.stringify(accounts, null, 4), 'utf8');
        logger.success(`Accounts saved to ${WALLET_FILE}`);
    } catch (e) {
        logger.error(`Error saving accounts: ${e.message}`);
    }
};

/**
 * Shows a continuous countdown timer.
 * @param {number} durationMs - The duration in milliseconds.
 * @param {string} message - The message prefix.
 */
const showCountdown = async (durationMs, message) => {
    let remaining = durationMs;
    while (remaining > 0) {
        const seconds = Math.floor(remaining / 1000);
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;

        const timeString = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
        logger.countdown(`${message} Next run in ${timeString}`);
        
        await delay(1000);
        remaining -= 1000;
    }
    // Clear the countdown line when done
    process.stdout.write('\r' + ' '.repeat(100) + '\r');
};


// --- CORE LOGIC ---

/**
 * Bot class to handle all interactions for a single account.
 */
class InsiderBot {
    /**
     * @param {string} privateKey - The private key for the account (can be null).
     * @param {string} id - The ID token from the account file.
     * @param {string|null} proxy - The HTTP/S proxy URL (e.g., http://user:pass@ip:port).
     */
    constructor(privateKey, id, proxy = null) {
        this.privateKey = privateKey;
        this.id = id;
        this.proxy = proxy;

        if (this.privateKey) {
            this.wallet = new ethers.Wallet(this.privateKey);
            this.address = this.wallet.address;
            this.provider = new ethers.JsonRpcProvider(RPC_URL);
            this.signer = this.wallet.connect(this.provider);
            logger.info(`Initialized Bot for address: ${this.address}`);
        } else {
            this.address = "N/A (No Private Key)";
            this.wallet = null;
            this.provider = null;
            this.signer = null;
            logger.warn(`Initialized Bot with ID: ${this.id} (No Private Key)`);
        }

        this.client = axios.create({
            baseURL: API_BASE_URL,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.id}`,
                'Accept': 'application/json'
            },
            ...(this.proxy && { httpsAgent: new HttpsProxyAgent(this.proxy) })
        });
    }

    /**
     * Executes the Faucet claim transaction.
     * @returns {Promise<string>} Transaction hash.
     */
    async faucetClaim() {
        logger.loading('Attempting to claim faucet...');
        const response = await this.client.post('/faucet', {
            address: this.address,
        });

        const { txHash, message } = response.data;
        if (txHash) {
            logger.success(`Faucet Claim Successful. Tx Hash: ${txHash}`);
            return txHash;
        } else {
            logger.warn(`Faucet endpoint returned: ${message || JSON.stringify(response.data)}`);
            return null;
        }
    }

    /**
     * Executes a Swap transaction.
     * @returns {Promise<string>} Transaction hash.
     */
    async swap() {
        logger.loading('Attempting to perform swap...');
        const response = await this.client.post('/swap', {
            address: this.address,
            // You might need to adjust the amount or token addresses based on current API requirements
            // This is a placeholder payload assuming a simple API interaction
            amount: 0.001, 
        });

        const { txHash, message } = response.data;
        if (txHash) {
            logger.success(`Swap Successful. Tx Hash: ${txHash}`);
            return txHash;
        } else {
             logger.warn(`Swap endpoint returned: ${message || JSON.stringify(response.data)}`);
             return null;
        }
    }

    /**
     * Sends a chat message to the agent.
     * @returns {Promise<void>}
     */
    async chatWithAgent() {
        logger.loading('Chatting with agent...');
        // The message content might need to be dynamic or configured
        const chatMessage = "Halo! Saya ingin berbicara tentang PulseChain."; 
        const response = await this.client.post('/chat', {
            message: chatMessage
        });
        
        logger.success(`Chat with Agent successful. Response: ${response.data.agentResponse || 'No specific response message.'}`);
    }

    /**
     * Collects all available Pulses.
     * @returns {Promise<void>}
     */
    async collectPulses() {
        logger.loading('Collecting all pulses...');
        const response = await this.client.post('/pulses/collect');
        
        logger.success(`Pulses collected. Total collected: ${response.data.pulsesCollected || 'N/A'}`);
    }

    /**
     * Claims all available tasks.
     * @returns {Promise<void>}
     */
    async claimTasks() {
        logger.loading('Claiming all available tasks...');
        const response = await this.client.post('/tasks/claim');
        
        const claimedCount = response.data.claimedTasks ? response.data.claimedTasks.length : 0;
        logger.success(`Tasks claimed. Total claimed: ${claimedCount}`);
    }
    
    /**
     * Checks the balance of native token (PLSED) and a specific token (e.g., test token).
     * Requires a private key to be set.
     * @returns {Promise<void>}
     */
    async checkBalances() {
        if (!this.signer) {
            logger.warn("Cannot check balances: No signer available (Private Key missing).");
            return;
        }

        logger.loading('Checking balances...');
        try {
            // Check native token (PLSED) balance
            const plsedBalance = await this.provider.getBalance(this.address);
            const plsedFormatted = ethers.formatEther(plsedBalance);

            // You might need to add logic for checking a specific token balance
            // For now, only checking native token:

            logger.info(`PLSED Balance: ${plsedFormatted} PLSED`);

        } catch (e) {
            logger.error(`Failed to check balances: ${e.message}`);
        }
    }
}

/**
 * Runs a function with retries on failure.
 * @param {Function} taskFn - The function to run.
 * @param {string} taskName - A descriptive name for the task.
 * @returns {Promise<any>} The result of the task.
 */
const runTaskWithRetries = async (taskFn, taskName) => {
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        try {
            logger.loading(`[${taskName}] Attempt ${attempt}/${MAX_RETRIES}...`);
            const result = await taskFn();
            logger.success(`[${taskName}] Completed successfully.`);
            return result;
        } catch (e) {
            const delayTime = 5000 * attempt;
            logger.warn(`[${taskName}] Attempt ${attempt} failed: ${e.message}. Retrying in ${delayTime / 1000}s...`);
            if (attempt < MAX_RETRIES) {
                await delay(delayTime);
            } else {
                logger.error(`[${taskName}] Failed after ${MAX_RETRIES} attempts.`);
                throw new Error(`Task failed: ${taskName}`);
            }
        }
    }
};

/**
 * Main application function.
 */
async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    let accounts = loadAccounts();

    // Loop for the main menu
    while (true) {
        logger.banner();
        logger.step("Main Menu");
        console.log("1. View Accounts");
        console.log("2. Add New Account (Private Key + ID)");
        console.log("3. Add New Account (ID Only)");
        console.log("4. Delete Account");
        console.log("5. Run Daily Tasks for All Accounts");
        console.log("6. Start Continuous Daily Runner");
        console.log("7. Exit");
        console.log(colors.gray + '-----------------------------------------' + colors.reset);

        const choice = await ask(rl, 'Choose an option: ');

        if (choice === '1') {
            logger.section('Account List');
            if (accounts.length === 0) {
                logger.info('No accounts loaded.');
            } else {
                accounts.forEach((acc, index) => {
                    const pkStatus = acc.privateKey ? colors.green + '[PK AVAILABLE]' + colors.reset : colors.yellow + '[PK MISSING]' + colors.reset;
                    logger.info(`${index + 1}. ID: ${acc.id.substring(0, 10)}... | PK Status: ${pkStatus} | Proxy: ${acc.proxy || 'N/A'}`);
                });
            }
            await ask(rl, '\nPress Enter to return to the main menu...');
        } 
        
        else if (choice === '2' || choice === '3') {
            logger.section('Add New Account');
            const id = await ask(rl, 'Enter Insider ID (Bearer Token): ');
            
            let privateKey = null;
            if (choice === '2') {
                privateKey = await ask(rl, 'Enter Private Key (Optional, press Enter to skip): ');
                if (privateKey === '') privateKey = null;
            }

            const proxy = await ask(rl, 'Enter HTTP Proxy URL (Optional, press Enter to skip): ');
            
            accounts.push({
                id: id.trim(),
                privateKey: privateKey ? privateKey.trim() : null,
                proxy: proxy.trim() || null
            });
            saveAccounts(accounts);
        }
        
        else if (choice === '4') {
            logger.section('Delete Account');
            if (accounts.length === 0) {
                logger.warn('No accounts to delete.');
                await ask(rl, '\nPress Enter to return to the main menu...');
                continue;
            }
            accounts.forEach((acc, index) => {
                logger.info(`${index + 1}. ID: ${acc.id.substring(0, 10)}... | Proxy: ${acc.proxy || 'N/A'}`);
            });
            const indexToDelete = parseInt(await ask(rl, 'Enter the number of the account to delete: '), 10);
            
            if (indexToDelete > 0 && indexToDelete <= accounts.length) {
                const deletedAccount = accounts.splice(indexToDelete - 1, 1);
                saveAccounts(accounts);
                logger.success(`Account with ID ${deletedAccount[0].id.substring(0, 10)}... deleted.`);
            } else {
                logger.error('Invalid account number.');
            }
            await ask(rl, '\nPress Enter to return to the main menu...');
        }
        
        else if (choice === '5' || choice === '6') {
            
            if (accounts.length === 0) {
                logger.critical('No accounts loaded. Please add an account first.');
                await ask(rl, '\nPress Enter to return to the main menu...');
                continue;
            }
            
            if (choice === '6') {
                logger.info("Starting continuous daily runner. Press Ctrl+C to stop.");
            }
            
            while (choice === '5' || choice === '6') {
                logger.section('STARTING DAILY RUN');

                for (const account of accounts) {
                    logger.step(`--- Processing Account ID: ${account.id.substring(0, 10)}... ---`);
                    const bot = new InsiderBot(account.privateKey, account.id, account.proxy);

                    try {
                        await delay(1000); // Small initial delay

                        // 1. On-Chain Tasks (requires Private Key)
                        if (bot.privateKey) {
                            logger.step("Starting On-Chain Tasks (Faucet, Swap, Balance Check)");
                            await runTaskWithRetries(() => bot.faucetClaim(), "Faucet Claim");
                            await delay(5000); // Cooldown for faucet/swap
                            
                            // Swap is often rate-limited or only done once
                            // Consider if you want to run this daily or once
                            // For now, let's run it daily as part of the process
                            await runTaskWithRetries(() => bot.swap(), "Token Swap");
                            await delay(5000); 
                            
                            await bot.checkBalances();

                        } else {
                            logger.warn(`Skipping on-chain tasks (Faucet, Swap) for Account ${account.id.substring(0, 10)}... - No Private Key.`);
                        }

                        // 2. Off-Chain/API Tasks (only requires ID/Bearer Token)
                        logger.step("Starting Off-Chain API Tasks (Chat, Pulses, Claim)");

                        await runTaskWithRetries(() => bot.chatWithAgent(), "Chat with Agent");
                        await delay(2000);

                        await runTaskWithRetries(() => bot.collectPulses(), "Collect All Pulses");
                        await delay(2000);

                        await runTaskWithRetries(() => bot.claimTasks(), "Claim All Available Tasks");

                    } catch (e) {
                        logger.error(`Critical error on Account ${account.id.substring(0, 10)}...: ${e.message}`);
                    }
                    logger.success(`--- Finished Account ${account.id.substring(0, 10)}... ---`);
                    await delay(2000); // Cooldown between accounts
                }
                
                logger.summary('--- DAILY RUN COMPLETED FOR ALL ACCOUNTS ---');

                if (choice === '5') {
                    // One-time run, exit inner loop
                    break;
                }
                
                // For Continuous Daily Runner (choice === '6')
                const DAILY_COOLDOWN_MS = 24 * 60 * 60 * 1000;
                await showCountdown(DAILY_COOLDOWN_MS, 'Waiting for next daily run...');
            
            }
        }

        else if (choice === '7') {
            logger.info('Exiting script. Goodbye!');
            rl.close();
            break;
        }

        else {
            logger.error('Invalid selection.');
            await ask(rl, '\nPress Enter to return to the main menu...');
        }
    }
}

// Start the application
main().catch(error => {
    logger.critical(`An unhandled error occurred: ${error.message}`);
    process.exit(1);
});
