pkstream
========

This project consist in pair of Java streams that can encrypt and decrypt a message.

The encryption is done using a public key, so that only the one having the private key can get the plain text.

These classes are ideal to have a public component (like an Android app) sending encrypted data to a server without having to configure SSL.
