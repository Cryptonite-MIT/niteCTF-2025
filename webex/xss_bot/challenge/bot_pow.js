const puppeteer = require("puppeteer");
const net = require("net");
const ProofOfWork = require("./pow");

const BOT_TIMEOUT = process.env.BOT_TIMEOUT || 15 * 1000;
const CHALLENGE_URL = process.env.CHALLENGE_URL || "https://notes.chals.nitectf25.live";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ubdgj5loTe5KKyiN5Eebvqcd51XAJ0rh2hIm82Q23ErR9Z3HDy";
const PORT = process.argv[2];
const POW_DIFFICULTY = process.env.POW_DIFFICULTY || 5;
const POW_TIMEOUT = process.env.POW_TIMEOUT || 30000;
const CHALLENGE = process.env.CHALLENGE || "JUST_ANOTHER_NOTES_APP";
const ALLOWED_SUBDOMAINS = process.env.ALLOWED_SUBDOMAINS ? process.env.ALLOWED_SUBDOMAINS.split(",").map((s) => s.trim()): [];

if (!PORT) {
  console.log("Listening port not provided");
  process.exit();
}
(async function () {
  const browser = await puppeteer.launch({
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-dev-shm-usage",
      "--disable-default-apps",
      "--disable-gpu",
      "--disable-sync",
      "--disable-translate",
      "--mute-audio",
      "--no-first-run",
      "--safebrowsing-disable-auto-update",
      "--js-flags=--noexpose_wasm,--jitless",
    ],
    ignoreHTTPSErrors: true,
  });
  async function load_url(socket, data) {
    let url = data.toString().trim();
    if (url === "testing") return;
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      socket.state = "ERROR";
      socket.write("Invalid scheme (http/https only).");
      socket.destroy();
      return;
    }
    socket.state = "LOADED";
    const context = await browser.createBrowserContext();
    const page = await context.newPage();

    page.on('console', msg => {
      console.log(`[PAGE CONSOLE] ${msg.type().toUpperCase()}: ${msg.text()}`);
    });

    console.log(ALLOWED_SUBDOMAINS)
    const validateUrl = (inputUrl) => {
    const parsedUrl = new URL(inputUrl);

    const hostnameParts = parsedUrl.hostname.split(".");
    if (hostnameParts.length < 3) {
       console.log("Length not enough");
      return false;
    }

      const subdomain = hostnameParts[0];
      if (!ALLOWED_SUBDOMAINS.includes(subdomain)) {
        console.log("Invalid Subdomain");
        console.log(subdomain);
        return false;
      }

      const domain = hostnameParts.slice(1).join(".");
      console.log(domain);
      if (domain !== "chals.nitectf25.live") {
        console.log("Invalid Domain");
        return false;
      }

      if (/[<@>]/.test(parsedUrl.pathname)) {
        console.log("Invalid chars in url");
        return false;
      }

      return true;
    };

    if (!validateUrl(url)) {
      socket.write("Invalid URL");
      socket.destroy();
      return;
    }

    if (CHALLENGE == "JUST_ANOTHER_NOTES_APP") {
      await page.goto(CHALLENGE_URL);

      const loginResponse = await page.evaluate(
        async (CHALLENGE_URL, ADMIN_USERNAME, ADMIN_PASSWORD) => {
          const response = await fetch(`${CHALLENGE_URL}/login`, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: `username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}`,
            redirect: "follow",
          });
          return response.ok;
        },
        CHALLENGE_URL,
        ADMIN_USERNAME,
        ADMIN_PASSWORD
      );

      if (!loginResponse) {
        socket.write("Admin visit failed.");
        console.log("admin login failed");
        socket.destroy();
        return;
      }
      console.log("admin login successful");
      await page.goto(url);
      socket.write("The admin has visited your url.");
      console.log("admin visited the url");
      socket.destroy();
    } else {
      socket.write("Bot is not set to not visit a url");
    }

    setTimeout(() => {
      context.close();
      socket.destroy();
    }, BOT_TIMEOUT);
  }

  const pow = new ProofOfWork(POW_DIFFICULTY, POW_TIMEOUT);
  const server = net.createServer(async (socket) => {
    try {

      await pow.handlePowVerification(socket);
      socket.on("data", (data) => {
        load_url(socket, data);
      });
    } catch (err) {
      console.log(`PoW Error: ${err}`);
      socket.destroy();
    }
  });

  server.listen(PORT);
  console.log(
    `Listening on port ${PORT} with PoW difficulty ${POW_DIFFICULTY}`
  );
})();
