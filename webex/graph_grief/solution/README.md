# Graph Grief

**Flag:** `nite{Th3_Qu4ntum_Ent1ty_H4s_B33n_Summ0n3d}`

[Solve script](solve.py)

This is a Node.js Apollo Server application exposing a GraphQL endpoint. Introspection is disabled, and critical endpoints are protected by IP whitelisting.

The application accepts `application/xml` requests, creating an **XXE (XML External Entity)** vulnerability. However, a custom WAF (`reject-file-xxe.js`) blocks standard local file inclusion schemes (like `file://`) but allows remote DTDs via HTTP/HTTPS.

The exploitation relies on chaining **OOB XXE** into **SSRF** to access internal endpoints running on `127.0.0.1:8000`.

### The Vulnerability Chain
1.  **XXE Injection:** The `/graphql` endpoint parses XML. By using a Parameter Entity, we can force the parser to fetch an external DTD from our malicious server.
2.  **Internal File Leak:** The app exposes `/internal/file`, which reads files from disk but only responds to localhost. We point our external DTD here to steal `schema.graphql`.
3.  **SSRF / Auth Bypass:** The flag is in a `secret` node restricted to `127.0.0.1`. We use the same XXE technique to hit `/internal/graphql`, making the server query itself to bypass the IP check.

### Solution Logic

The solution script performs the following steps:

1.  **Leak Schema:**
    * Hosts a DTD pointing to `http://127.0.0.1:8000/internal/file?name=schema.graphql`.
    * Sends XML to `/graphql` referencing this DTD.
    * Decodes the Base64 response to reveal the schema.

2.  **Reconnaissance:**
    * Queries `auditLogs` (publicly accessible) to find the ID of the flag node: `secret:flag`.
    * Analysis of the leaked schema confirms a `secret` type exists but is inaccessible externally.

3.  **Retrieve Flag:**
    * Constructs a GraphQL query for the secret node: `{node(id:"..."){...on secret{flag}}}`.
    * Hosts a second DTD pointing to `http://127.0.0.1:8000/internal/graphql?query=<encoded_query>`.
    * Sends the XML payload. The server executes the query locally (as localhost) and returns the flag.
