# Single Sign Off

**Flag:** `nite{r3dir3ct_l3ak_r3p3at}`

Through the dockerfile, we find the Document Portal (which runs a libcurl binary) uses a .netrc file to attach credentials to certain services.

```
echo 'machine nite-sso' >> /root/.netrc && \
echo "  login niteuser" >> /root/.netrc && \
echo "  password nitepass" >> /root/.netrc && \
.
.
.
echo 'default' >> /root/.netrc && \
```

Document Portal is running `curl 7.80.0` which is vulnerable to [CVE-2025-0167](https://curl.se/docs/CVE-2025-0167.html), which allows for credentials to be leaked via a redirect from the intended service when the .netrc file contains an empty default entry.

The credentials required to access nite vault are those of nite-sso in the .netrc file. Going through source code of nite-sso, we find the `doLogin` endpoint which allows for open redirects. This allows us set up a service, redirect a request from nite-sso, using an internal ssrf, to it using the fetcher via doLogin endpoint and steal credentials.

Refer [capture.py](./capture.py) for this. (for capturing credentials, we must first return a 401 to make libcurl attach credentials)

Following this credentials for nite vault can be obtained.

However nite vault is still inacessible as it is blacklisted by Document Portal.

To access this, we find the error handling for `CURLE_TOO_MANY_REDIRECTS` is flawed, and doesn't vallidate the final redirect after redirect limit is reached.

This allows to access nite vault after a loop of 5 redirects. Refer [redirector.py](./redirector.py).

In nite vault the view endpoint is vulnerable to lfi, which allows us to reference all files via absolute path.

The flag file's name is generated via a PRNG with seed values containing pid, uid, gid. All three of these values can be found in /proc/self/status.

