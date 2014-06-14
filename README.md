![CRYPTAUR](https://raw.githubusercontent.com/cryptosphere/cryptor/master/cryptosaur.png)
Cryptor
=======
[![Gem Version](https://badge.fury.io/rb/cryptor.png)](http://badge.fury.io/rb/cryptor)
[![Build Status](https://travis-ci.org/cryptosphere/cryptor.png?branch=master)](https://travis-ci.org/cryptosphere/cryptor)
[![Code Climate](https://codeclimate.com/github/cryptosphere/cryptor.png)](https://codeclimate.com/github/cryptosphere/cryptor)
[![Coverage Status](https://coveralls.io/repos/cryptosphere/cryptor/badge.png?branch=master)](https://coveralls.io/r/cryptosphere/cryptor?branch=master)

A safe Ruby encryption library, designed to support features like multiple
active encryption keys and key rotation.

Cryptor uses [authenticated encryption] *exclusively*, ensuring your data
remains untamered with, even when it's in the hands of an attacker.

Cryptor supports two backends:

* [RbNaCl::SimpleBox]: (default) authenticated symmetric encryption based on
  XSalsa20+Poly1305 from [libsodium].
* [ActiveSupport::MessageEncryptor]: (Rails 4+) a bespoke authenticated
  encryption scheme provided by Rails, based on AES-CBC and HMAC.

Cryptor uses the experimental [ORDO v0 message format][ordo] for serializing
encrypted messages. Future versions may support additional message formats
like OpenPGP or JWE.

[authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
[RbNaCl::SimpleBox]: https://github.com/cryptosphere/rbnacl/wiki/SimpleBox
[libsodium]: https://github.com/jedisct1/libsodium/
[ActiveSupport::MessageEncryptor]: http://api.rubyonrails.org/classes/ActiveSupport/MessageEncryptor.html
[ordo]: https://github.com/cryptosphere/ordo/wiki/Message-Format

## Installation

Add this line to your application's Gemfile:

    gem 'cryptor'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cryptor

## Usage

To begin with, you must select a backend:

### RbNaCl (recommended)

RbNaCl is a Ruby FFI binding to libsodium, a portable state-of-the-art
cryptography library.

To use Cryptor with RbNaCl, add the following to your Gemfile:

```ruby
gem 'rbnacl-libsodium'
```

And in your Ruby program, require the following:

```ruby
require 'cryptor'
require 'cryptor/symmetric_encryption/ciphers/xsalsa20poly1305'
```

### Rails (ActiveSupport::MessageEncryptor)

Cryptor can use ActiveSupport 4.0+'s `MessageEncryptor` class to encrypt
messages. This scheme uses AES-256 in CBC mode for encryption and HMAC-SHA1
to provide ciphertext integrity.

This option is only recommended if you have some compliance issues which
mandate the use of NIST ciphers or if you have problems installing
the rbnacl-libsodium gem or libsodium library for some reason.

To use Cryptor with ActiveSupport::MessageEncryptor, require the following
from a Rails 4.0+ app or other app with ActiveSupport 4.0+ bundled:

```ruby
require 'cryptor'
require 'cryptor/symmetric_encryption/ciphers/message_encryptor'
```

### Authenticated Symmetric Encryption

To encrypt data with Cryptor, you must first make a secret key to encrypt it
under. Use the following for RbNaCl:

```ruby
# Make a RbNaCl secret key
secret_key = Cryptor::SymmetricEncryption.random_key(:xsalsa20poly1305)
```

or the following for ActiveSupport::MessageEncryptor:

```ruby
# Make an ActiveSupport secret key
secret_key = Cryptor::SymmetricEncryption.random_key(:message_encryptor)
```

Inspecting a secret key looks like this:

```
#<Cryptor::SecretKey:0x81438830 cipher=xsalsa20poly1305 fingerprint=ni:///sha-256;Wy8hx4...>
```

You can't actually see the secret key itself by calling `#inspect` or `#to_s`.
This is to prevent accidentally logging the secret key. Instead you can only
see the key's fingerprint, which is given as a [RFC 6920] hash URI of the secret
key's [ORDO secret URI].

To obtain the secret URI, use the `#to_secret_uri` method, which returns a string:

```ruby
>> secret_key.to_secret_uri
=> "secret.key:///xsalsa20poly1305;0saB1tfgKWDh_bX0oAquLWgAq-6yjG1u04mP-CtQG-4"
```

This string can be saved somewhere secret and safe then later loaded and passed into
`Cryptor::SymmetricEncryption.new`:

```ruby
cryptor = Cryptor::SymmetricEncryption.new("secret.key:///xsalsa20poly1305;0saB...")
```

After this, you can encrypt with the `#encrypt` method:

```ruby
ciphertext = cryptor.encrypt(plaintext)
```

and decrypt with the `#decrypt` method:

```ruby
decrypted = cryptor.decrypt(ciphertext)
```

[RFC 6920]: http://tools.ietf.org/html/rfc6920
[ORDO secret URI]: https://github.com/cryptosphere/ordo/wiki/URI-Registry

## Key Rotation

Cryptor is designed to support key rotation, allowing new ciphertexts to be
produced under an "active" key, but with old keys configured so older
ciphertexts can still be decrypted (and also rotated to the new key).

To rotate keys, first make a new key, but configure Cryptor with the old key
too using the "keyring" option:

```ruby
old_key = ...
new_key = Cryptor::SymmetricEncryption.random_key(:xsalsa20poly1305)
cryptor = Cryptor::SymmetricEncryption.new(new_key, keyring: [old_key])
```

Cryptor can support arbitrarily many old keys on its keyring. Any messages
which have been encrypted under the old keys can still be decrypted, but
newly encrypted messages will always use the new "active" key.

To rotate messages from one key to another, use the `#rotate` method:

```ruby
old_message = ...
new_message = cryptor.rotate(old_message)
```

This is useful if a key is ever compromised, and also good security hygene
in general.

Cryptor also supports the `#rotate!` method, which works just like `#rotate`,
but raises `Cryptor::AlreadyRotatedError` if asked to rotate a message that's
already up-to-date.

## Contributing

* Fork this repository on Github
* Make your changes and send a pull request
* If your changes look good, we'll merge 'em

## License

Copyright (c) 2014 Tony Arcieri.
Distributed under the MIT License. See LICENSE.txt for further details.
