## Tools for generating bad MIME

- gen_variants_hide_content.pl
  Create Mailbox with lots of mails which packs specific attachment into various
  forms of bad MIME. These generated mails are then used to test which MUA can
  extract the mails and which security products fail to detect the attacht
  malware or fail to enforce a sane interpretation.
  Default output location is maildir hide-content.d/.
  Default attachment is eicar.zip.
- gen_variants_hide_filename.pl
  Similar to gen_variants_hide_content.pl but creates mails which hide the real
  filename in various ways. Used to test ability of AV etc to block attachments
  by extension.
- MimeGen/ (MimeGen::*)
  modules used in gen_variants_hide_content.pl and gen_variants_hide_filename.pl
  to create mails

## Tools for using bad MIME in tests

- maildir2pcap.pl
  Create pcap(s) with from maildir. These pcap simulate SMTP session(s)
  transporting these mails. Used to test against IDS like Snort and Suricata
  which can read pcap files. Each SMTP session is a different port for easier
  analysis of logs and the generated *.manifest file has the mapping
- minimal-smtp-client.pl, minimal-smtp-server.pl
  Small SMTP client and server. Adjust code inside for changing ports etc
- pop-client.pl, pop-server.pl
  Tools to test quality of POP3 analysis in firewalls
  pop-server provides POP server on maildir where the first mail is a manifest
  of all the mails.  pop-client is the pendant, i.e. gets the manifest, rerieves
  the mails and looks for changes, typically because the mail got blocked or the
  malware removed
- verify-chksum.pl
  check if the checksum contained in the mail header still matches the mail.
  This is used to detect if the mail transport has changed the mail, like
  removing malware or sanitization.


