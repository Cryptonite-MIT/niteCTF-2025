# Just Another Notes App

**Flag:** `nite{r3qu3575_d0n7_n33d_70_4lw4y5_c0mpl373}`

The challenge was based on [this](https://castilho.sh/scream-until-escalates) article and the intention was to use the 431 status code trick to leak the admin invite token. Here is the intended flow of the exploit in the ideal case:

Gunicorn has limit of 8187 on header size. So if a request has cookies of total size greater than that it causes a 431 status code and the request fails. We can use this in certain conditions to access redirect url's when in general the url in Location header is not accessible directly when using the Fetch API - https://stackoverflow.com/questions/43344819/reading-response-headers-with-fetch-api

Now if we set cookies of total length just shorter than that when FinalToken is inserted and request is redirected to the url with the token in query param the total size of headers for that request exceeds the limit and the request fails with 431 status code causing the token to get leaked to javascript.

Now connect-src is 'self' in the csp so you cannot directly exfiltrate the token to an external webhook.The easiest way to bypass this was to make the admin bot post the token as a note using your session cookies so that you can then access it in your account.

Using the exfiltrated token you can then promote yourself to admin and get the flag cookie. You cannot get it using xss directly because the cookie is httpOnly so even if you make the admin bot call /admin in the script the flag will not be accessible to javascript.

[Solve script](solve.py)

The challenge had a few unintended solutions due to insufficient hardening causing token leak without needing to use the above exploit.

