require 'cryptor/version'

require 'cryptor/cipher'
require 'cryptor/encoding'
require 'cryptor/secret_key'
require 'cryptor/symmetric_encryption'

# Multi-backend high-level encryption library
module Cryptor
  CryptoError = Class.new(StandardError)

  InvalidMessageError   = Class.new(CryptoError)
  CorruptedMessageError = Class.new(CryptoError)
end
