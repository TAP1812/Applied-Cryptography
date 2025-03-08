# KeyChain - Password Manager Application

## Requirements
- `Nodejs`: [https://nodejs.org/en/download/]
## How to run ?
- `npm install --save-dev mocha`
- `npm test`

## Short-answer Questions

- <b>Briefly describe your method for preventing the adversary from learning information about
the lengths of the passwords stored in your password manager ?</b><br>
=> We use PKCS#7 padding to ensure that all encrypted passwords have the same length, equal to `MAX_PASSWORD_LENGTH`. Before encrypting a password, we pad it to the full length. When retrieving, we removed PKCS#7 to get back the original message. This makes it impossible for an adversary to infer the length of the original password by observing the size of the encrypted data. Also the code implemented throws an error if the padding length is incorrect to prevent an attack.

- <b>Briefly describe your method for preventing swap attacks (Section 2.2). Provide an argument
for why the attack is prevented in your scheme ?</b><br>
=> I prevent swap attacks by calculating `tag = HMAC(hmacKey, password + HMAC(hmacKey, domain))`, where hmacKey is the same key used for both domain HMACs and tag generation. When retrieving a password, the tag is recalculated and compared to the stored tag. If they don't match, it indicates a swap or modification. While this approach is simpler, it's important to note that it relies on the security of the single hmacKey. If an attacker obtains this key, they could forge valid tags.

- <b>In our proposed defense against the rollback attack (Section 2.2), we assume that we can store
the SHA-256 hash in a trusted location beyond the reach of an adversary. Is it necessary to
assume that such a trusted location exists, in order to defend against rollback attacks? Briefly
justify your answer.</b><br>
=> Yes, assuming a trusted location for the SHA-256 hash is crucial. Without it, an adversary who gains access to the serialized password database could replace it with an older version. Without a securely stored hash to compare against, the password manager would have no way to detect that a rollback attack has occurred. An attacker may revert the system to a vulnerable or exploitable state by gaining access to a previous state.

- <b>Because HMAC is a deterministic MAC (that is, its output is the same if it is run multiple
times with the same input), we were able to look up domain names using their HMAC values.
There are also randomized MACs, which can output different tags on multiple runs with the
same input. Explain how you would do the look up if you had to use a randomized MAC
instead of HMAC. Is there a performance penalty involved, and if so, what?</b><br>
=> With a randomized MAC, since the output changes on each run even with the same input, we can no longer use the MAC value as the direct key for the key-value store (KVS). We would need to store all the (randomized MAC, ciphertext) pairs in a list, and to look up a domain name, we'd need to iterate over the entire list, computing the randomized MAC of the domain name for each entry in the list and compare to see if there's a match. There is a performance penalty involved since the lookup would be O(n), where n is the number of stored passwords, instead of O(1) with the deterministic HMAC.

- <b>In our specification, we leak the number of records in the password manager. Describe an
approach to reduce the information leaked about the number of records. Specifically, if there
are k records, your scheme should only leak ⌊log2(k)⌋ (that is, if k1 and k2 are such that
⌊log2(k1)⌋ = ⌊log2(k2)⌋, the attacker should not be able to distinguish between a case where
the true number of records is k1 and another case where the true number of records is k2).</b><br>
=> To leak only ⌊log₂(k)⌋, we can pad the database with dummy records until the number of records is a power of 2. Let p be the smallest non-negative integer such that k + padding = 2^p.
When returning the database size to the user, we return the value of p, which will leak approximately log₂(k). Since 2^⌊log₂(k)⌋ <= k < 2^(⌊log₂(k)⌋+1), this will hide the actual number of entries to within a power of 2.
For example, if k = 10 (records), then ⌊log₂(10)⌋ = 3. The attacker will only learn that the database size is between 2^3=8 and 2^(3+1)=16.
If the amount of dummy records were increased so that k = 16 (records), then ⌊log₂(16)⌋ = 4. The attacker will only learn that the database size is between 2^4=16 and 2^(4+1)=32.
The actual database size would range between 8 and 15.

- <b>What is a way we can add multi-user support for specific sites to our password manager
system without compromising security for other sites that these users may wish to store
passwords of? That is, if Alice and Bob wish to access one stored password (say for nytimes)
that either of them can get and update, without allowing the other to access their passwords
for other websites.</b><br>
=> To add multi-user support for specific sites, like nytimes.com for Alice and Bob, I would implement a shared keychain. Each user would still have their individual keychains, protected by their personal master passwords. However, for sites they wish to share, instead of storing the password in their personal keychain, a reference would be stored, pointing to an entry in a separate, shared keychain. This shared keychain would then be protected by a separate authentication mechanism. When Alice (or Bob) attempt to access nytimes.com, their password manager would detect the reference to the shared keychain, and instead retrieve credentials by authenticating them against the shared keychain. Other passwords will be unaffected.
