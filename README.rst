bsex - Botan based stream cipher utility
========================================

bsex is a small utility based on cryptographic functions provided by `Botan`_
library to perform encryption and decryption of file streams/pipes on POSIX
style systems.

Main motivation for developing this tool has been that GnuPG doesn't support
use case of running automated encrypted backups from cronjob with standard
tar and compression utilities.

Design
------

Currently two key pairs are created. RSA keypair for encrypting symmetric key
and IV. And Ed25519 key for signatures. Keys are stored using X.509 and
PKCS #8.

For actual stream cipher, AES is used in CTR mode. Signature is computed for
the plaintext to verify correctness of the data end-to-end.

User performing backup can encrypt the backup for specified "recipient" key
and sign it with his own key.

Vice versa, on backup restore/decryption, user performing restore can then
decrypt the backup using his own key and verify it against backup creator's
key.

This allows creating backups of encrypted storage on unsafe target media,
such as typical NAS or unencrypted external (USB) HDD.

License
-------

bsex is licensed under similar license as Botan library it is using. Meaning
"two-clause" or "simplified" BSD license.

Build notes
-----------

Only other dependency apart from C++11 compiler/STL is `Botan`_ library,
at minimum version 2.8.0 due to required API functions.

Usage examples
--------------

Following command line creates compressed backup and encrypts it for public
key of "myrecipient". Usually you would have automated backup user id with
it's own keys, and a separate personal user id with it's own key for
extracting backups when necessary. This way the user who created the backups
cannot extract the backup after it has been created and backup target media
can be unsafe. Likewise, recipient can extract the backup and verify that it
indeed was delivered unmodified from the backup user.

::

  tar -c -f - myfolder | pxz -9 -c | bsex encrypt myrecipient /media/unsafe/mybackup.tar.xz.bsex

Following command line extracts the backup from backup user "mysender".

::

  bsex decrypt mysender /media/unsafe/backup.tar.xz.bsex | pxz -d -c | tar -x -f -


.. _Botan: https://botan.randombit.net
