const puppeteer = require('puppeteer');

const TARGET = process.env.VICTIM_URL;
const USER = 'user';
const PASS = 'demo123';

const isValidTarget = (url, target) => {
    try {
        const urlObj = new URL(url);
        const targetObj = new URL(target);

        
        if (urlObj.origin === targetObj.origin) return true;

        
        if (['web', 'localhost', '127.0.0.1'].includes(urlObj.hostname)) return true;

        
        if (urlObj.hostname === 'cars.chalz.nitectf25.live') return true;

        return false;
    } catch (e) {
        return false;
    }
};

class Bot {
    constructor() {
        this.browser = null;
    }

    async init() {
        this.browser = await puppeteer.launch({
            executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage'

            ]
        });
    }

    async close() {
        if (this.browser) {
            await this.browser.close();
            this.browser = null;
        }
    }

    async auth(leakUrl) {
        const page = await this.browser.newPage();
        let tok = null;
        let leaked = false;
        let leakResourceUrl = null;

        try {
            const botSecret = process.env.BOT_SECRET;
            if (!botSecret) {
                throw new Error('variable not set');
            }

            await page.setRequestInterception(true);

            const requestHandler = (req) => {
                const referer = req.headers()['referer'] || req.headers()['referrer'];
                const reqUrl = req.url();

                if (referer && referer.includes('token=')) {
                    leaked = true;
                    leakResourceUrl = reqUrl;
                }

                const headers = { ...req.headers() };
                if (isValidTarget(reqUrl, TARGET)) {
                    console.log(`[BOT] Injecting Secret Header for: ${reqUrl}`);
                    headers['X-Bot-Secret'] = botSecret;
                } else {
                    console.log(`[BOT] SKIPPING Secret Header for: ${reqUrl} (TARGET: ${TARGET})`);
                }

                req.continue({ headers }).catch(() => { });
            };

            page.on('request', requestHandler);

            page.on('framenavigated', (frame) => {
                if (frame === page.mainFrame()) {
                    const url = frame.url();
                    if (url.includes('/auth/callback') && url.includes('token=')) {
                        const urlObj = new URL(url);
                        tok = urlObj.searchParams.get('token');
                    }
                }
            });

            await page.goto(`${TARGET}/login`, { waitUntil: 'networkidle0' });

            if (leakUrl) {
                await page.evaluate((url) => {
                    const form = document.querySelector('form');
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'leakUrl';
                    input.value = url;
                    form.appendChild(input);
                }, leakUrl);
            }

            await page.type('#username', USER);
            await page.type('#password', PASS);

            await Promise.all([
                page.waitForNavigation({ waitUntil: 'networkidle0' }),
                page.click('button[type="submit"]')
            ]);

            await page.waitForTimeout(2000);

            page.off('request', requestHandler);
            await page.setRequestInterception(false);

            if (tok) {
                return {
                    success: true,
                    token: tok,
                    page: page,
                    leaked: leaked,
                    leakResourceUrl: leakResourceUrl
                };
            } else {
                await page.close();
                return { success: false, page: null };
            }
        } catch (error) {
            await page.close();
            return { success: false, page: null };
        }
    }

    async visit(url, page, tok) {
        try {
            let leaked = false;
            let leakUrl = null;
            const botSecret = process.env.BOT_SECRET;

            await page.setRequestInterception(true);

            const handler = (req) => {
                const referer = req.headers()['referer'] || req.headers()['referrer'];

                if (referer && referer.includes('token=')) {
                    leaked = true;
                    leakUrl = req.url();
                }

                const headers = { ...req.headers() };
                if (isValidTarget(req.url(), TARGET)) {
                    console.log(`[BOT] Injecting Secret Header for: ${req.url()}`);
                    headers['X-Bot-Secret'] = botSecret;
                } else {
                    console.log(`[BOT] SKIPPING Secret Header for: ${req.url()} (TARGET: ${TARGET})`);
                }

                req.continue({ headers }).catch(() => { });
            };

            page.on('request', handler);

            try {
                await page.goto(url, {
                    waitUntil: 'networkidle0',
                    timeout: 15000
                });
            } catch (navError) {
            }


            page.off('request', handler);
            await page.setRequestInterception(false);

            if (leaked) {
                return {
                    success: true,
                    vulnerable: true
                };
            }

            return { success: false, vulnerable: false };
        } catch (error) {
            return { success: false, vulnerable: false, error: error.message };
        }
    }

    async run(url) {
        try {
            await this.init();
            const result = await this.auth(url);

            if (!result.success) {
                await this.close();
                return { success: false, vulnerable: false };
            }

            if (result.leaked) {
                await result.page.close();
                await this.close();
                return {
                    success: true,
                    vulnerable: true
                };
            }

            const data = await this.visit(
                url,
                result.page,
                result.token
            );

            await result.page.close();
            await this.close();

            return data;
        } catch (error) {
            await this.close();
            return { success: false, vulnerable: false, error: error.message };
        }
    }
}

module.exports = Bot;
