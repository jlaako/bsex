bsex - Botan based stream cipher utility
========================================

bsex is a small utility based on cryptographic functions provided by Botan
library to perform encryption and decryption of file streams/pipes on posix
style systems.

Design
------

Currently two key pairs are created. RSA keypair for encrypting symmetric key
and IV. And Ed25519 key for signatures.

For actual stream cipher, AES is used in CTR mode. Signature is computed for
the plaintext to verify correctness of the data end-to-end.

User performing backup can encrypt the backup for specified "recipient" key
and sign it with his own key.

Vice versa, on backup restore/decryption, user performing restore can then
decrypt the backup using his own key and verify it against backup creator's
key.


License
-------

bsex is licensed under similar license as Botan library it is using. Meaning
"two-clause" or "simplified" BSD license.
