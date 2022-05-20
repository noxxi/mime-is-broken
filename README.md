# Toolkit for generating and testing bad MIME

This is a toolkit for generating mails which broken MIME in order to test
behavior of MUA and security products, i.e. if they align or if broken MIME
could be used to bypass a security product.

## Files

- tools/*
  Tools for creating broken mails and testing. See README.md there
  Pre-generated mails are in hide-content.d and hide-filename.d
- hide-content.d/
  Maildir with generated mails for hiding the content (eicar.zip)
- hide-filename.d/
  Maildir with generated mails for hiding the real filename (file.zip)
- libtests/
  Tools for testing MIME libraries of various programming languages

## Format of generated Mails

- each mails contains a subject like
  [1] multipart-basic-singlepart-b64h-basic-base64-ws-space eicar.zip 2022-05-18 23:07
   |      |                                                   |         |
   |      |                                                   |         |- generated
   |      |                                                   |- attachment
   |      |- id describing the kind of test
   |- validity level
- each mail contains a similar X-Payload header, which also has the md5 over the
  content for later checking if the content was changed during transfer
  X-Payload-Id: multipart-basic-singlepart-b64h-basic-base64-ws-space valid(1)  md5(tSLKcoU0Lv+ZD4iR+BKYDA) eicar.zip 2022-05-18 23:07

- The validity level can be
  - 3: totally valid, no tricks. Used to make sure that analysis works at all
  - 2: fully conforming to standard, but some edge cases
  - 1: likely not like the standard was meant to be used, but not actually off
  - 0: definitely off from standard, but implementations might still interpret
       it in a somehow meaningful way
