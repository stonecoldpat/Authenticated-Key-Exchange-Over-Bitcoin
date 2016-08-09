Authenticated Key Exchange over Bitcoin
================================

https://eprint.iacr.org/2015/308.pdf


What is this code about? 
----------------

In 2013/2014, we modified the Bitcoin code case to include a few new RPC commands. This allows two parties to perform Diffie Hellman Key Exchange over Bitcoin, and YAK over Bitcoin, to establish an authenticated and secure end to end communication channel. 

We have modified the rpcrawtransaction.cpp to include the new commands, and key.cpp to allow us to extract the random ‘k’ value from the owner’s ECDSA signature. We need ‘k’ which is the random nonce generated for each signature to boot-strap the key exchange. 

Of course, as outlined in the paper, both ‘k’ the random nonce, or ‘d’ the private key can be used to bootstrap the key exchange. In this implementation we chose to use ‘k’, but this can be changed. Furthermore, we assume both users are using Script-to-Pubkey-Hash to demonstrate how the technique works. Further work to modify this implementation would allow it to work with other script-types (i.e. multisig, or OP_SCHNORR). 

We have three new functions:

getdiffiesecret # Performs the non-interactive key exchange

getyakzkp # Fetches ZKP that needs to be passed to your partner

getyaksecret # Given your partners ZKP, partner’s TXID, and your own secret ‘k’,’w’, compute the shared secret. 

It is worth looking at the example in zkptest to check how to perform the YAK Key Exchange.

Remember, we provide no warranty with this code, and there could be bugs/mistakes. If you find any problems, please contact me at patrick.mccorry@ncl.ac.uk and we will get it fixed asap. Furthermore, this code base is from 2013-2014. While it remains compatible with the Bitcoin network - it would be better to use this code as a basis to understand what is going on, and then include it in a more up to date code base, which I hope to do at some point. 

For historical fun - the following is the README.md from the Bitcoin code base from back then <3


What is Bitcoin?
----------------

Bitcoin is an experimental new digital currency that enables instant payments to
anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. Bitcoin is also the name of the open source
software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Bitcoin client software, see http://www.bitcoin.org.

License
-------

Bitcoin is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see http://opensource.org/licenses/MIT.

Development process
-------------------

Developers work in their own trees, then submit pull requests when they think
their feature or bug fix is ready.

If it is a simple/trivial/non-controversial change, then one of the Bitcoin
development team members simply pulls it.

If it is a *more complicated or potentially controversial* change, then the patch
submitter will be asked to start a discussion (if they haven't already) on the
[mailing list](http://sourceforge.net/mailarchive/forum.php?forum_name=bitcoin-development).

The patch will be accepted if there is broad consensus that it is a good thing.
Developers should expect to rework and resubmit patches if the code doesn't
match the project's coding conventions (see [doc/coding.md](doc/coding.md)) or are
controversial.

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/bitcoin/bitcoin/tags) are created
regularly to indicate new official, stable release versions of Bitcoin.

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test. Please be patient and help out, and
remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write unit tests for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run (assuming they weren't disabled in configure) with: `make check`

Every pull request is built for both Windows and Linux on a dedicated server,
and unit and sanity tests are automatically run. The binaries produced may be
used for manual QA testing — a link to them will appear in a comment on the
pull request posted by [BitcoinPullTester](https://github.com/BitcoinPullTester). See https://github.com/TheBlueMatt/test-scripts
for the build/test scripts.

### Manual Quality Assurance (QA) Testing

Large changes should have a test plan, and should be tested by somebody other
than the developer who wrote the code.
See https://github.com/bitcoin/QA/ for how to create a test plan.
