Cryptor
=======

A safe Ruby encryption library, designed to support features like multiple
active encryption keys and key rotation.

Cryptor uses [authenticated encryption] *exclusively*, ensuring your data
remains untamered with, even when it's in the hands of an attacker.

Cryptor supports two backends:

* [ActiveSupport::MessageEncryptor] (Rails 4+): a bespoke authenticated
  encryption scheme provided by Rails, based on AES-CBC and HMAC.
* [RbNaCl::SimpleBox]: authenticated symmetric encryption based on
  XSalsa20+Poly1305 from libsodium.

[authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
[ActiveSupport::MessageEncryptor]: http://api.rubyonrails.org/classes/ActiveSupport/MessageEncryptor.html
[RbNaCl::SimpleBox]: https://github.com/cryptosphere/rbnacl/wiki/SimpleBox

## Installation

Add this line to your application's Gemfile:

    gem 'cryptor'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cryptor

## Usage

TODO: Write usage instructions here

## Contributing

* Fork this repository on Github
* Make your changes and send a pull request
* If your changes look good, we'll merge 'em

## License

Copyright (c) 2014 Tony Arcieri.
Distributed under the MIT License. See LICENSE.txt for further details.
