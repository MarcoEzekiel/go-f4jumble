
# f4jumble

A golang implementation of F4Jumble

This Package provides a mechanism for "jumbling" byte slices in a reversible way.

Many byte encodings such as [Base64] and [Bech32] do not have "cascading" behaviour:
changing an input byte at one position has no effect on the encoding of bytes at
distant positions. This can be a problem if users generally check the correctness of
encoded strings by eye, as they will tend to only check the first and/or last few
characters of the encoded string. In some situations (for example, a hardware device
displaying on its screen an encoded string provided by an untrusted computer), it is
potentially feasible for an adversary to change some internal portion of the encoded
string in a way that is beneficial to them, without the user noticing.

[Base64]: https://en.wikipedia.org/wiki/Base64
[Bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Bech32

The function F4Jumble (and its inverse function, F4Jumble⁻¹) are length-preserving
transformations can be used to trivially introduce cascading behaviour to existing
encodings:

- Prepare the raw `message` bytes.
- Pass `message` through [F4jumble] to obtain the jumbled bytes.
- Encode the jumbled bytes with the encoding scheme.

Changing any byte of `message` will result in a completely different sequence of
jumbled bytes. Specifically, F4Jumble uses an unkeyed 4-round Feistel construction to
approximate a random permutation.

[Diagram of 4-round unkeyed Feistel construction](https://zips.z.cash/zip-0316-f4.png)
