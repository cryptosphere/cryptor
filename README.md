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
* [ActiveSupport::MessageEncryptor] (Rails 4+): a bespoke authenticated
  encryption scheme provided by Rails, based on AES-CBC and HMAC.

[authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
[RbNaCl::SimpleBox]: https://github.com/cryptosphere/rbnacl/wiki/SimpleBox
[libsodium]: https://github.com/jedisct1/libsodium/
[ActiveSupport::MessageEncryptor]: http://api.rubyonrails.org/classes/ActiveSupport/MessageEncryptor.html

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
