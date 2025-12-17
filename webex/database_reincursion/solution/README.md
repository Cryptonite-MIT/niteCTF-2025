# Database Reincursion

**Flag:** `nite{neVeR_9Onn4_57OP_WonDER1N9_1f_175_5ql_oR_5EKWeL}`

stage 1:

We are presented with a basic login page, on trying various inputs, the following can be ascertained:

- the following strings are blacklist:
    - `or`
    - `--`
- inputs are limited to a maximum of 60 characters

We need a basic SQLI payload to bypass the login page, given the above restrictions

Working paylods:

- `' IS NOT NULL/*`
- `' IN (0,1)/*`
- `' IN (FALSE, TRUE)/*`
- `' BETWEEN 0 AND 1/*`

stage 2:

In stage 2 we are presented with a directory where we can search by employee name, with each directory entry containing an employee's name, department, email address, and a small note. The page also contains form which requires a passcode in order to enter the admin page.

On trying various inputs, the same restrictions from the previous stage are discovered.

The employee `Drake`'s entry contains a note stating `I heard Kiwi from Management has the passcode`

So we have our target, the entry containing `department = 'Management'` and `name = 'Kiwi`

Required SQLI payload can be formed combining this with the information that the search bar queries by name (the search query is something along the lines of `select * from employees where name = $'variable'`).

Working payload:

`Kiwi' AND department = 'Management' /*`

stage 3:

In stage 3 we are presented with a reports directory that shows financial data with a search function which uses the 'quarter' column of the table.

We again find the same restrctions placed upon our inputs.

Below this is a 'metadata registry' which appears to include information regarding all the tables in the database, excluding 1 table with all values marked `REDACTED`.

In the registry we find a table labelled `metadata` which supposedly `Lists tables in this system`.

We can find the contents of metadata using a union payload combining it with the reports table given above.

`' UNION SELECT * FROM metadata /*`

With this we find the redacted table, `CITADEL_ARCHIVE_2077` with a column `secrets`

So, to get it's contents we can again use union, accounting for the missing columns in CITADEL_ARCHIVE_2077 which are present in the reports table.

Working Payload:

`'UNION SELECT 1,secrets,'x','x' FROM CITADEL_ARCHIVE_2077/*`
