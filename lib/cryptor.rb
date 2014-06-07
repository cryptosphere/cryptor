require 'cryptor/version'

require 'cryptor/cipher'
require 'cryptor/encoding'
require 'cryptor/secret_key'
require 'cryptor/symmetric_encryption'

module Cryptor
  CryptoError = Class.new(StandardError)
  InvalidMessageError = Class.new(CryptoError)
end
