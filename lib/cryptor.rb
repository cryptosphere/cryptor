require 'cryptor/version'

require 'cryptor/encoding'
require 'cryptor/symmetric_encryption'

# Multi-backend high-level encryption library
module Cryptor
  CryptoError = Class.new(StandardError)

  InvalidMessageError   = Class.new(CryptoError)
  CorruptedMessageError = Class.new(CryptoError)
  KeyNotFoundError      = Class.new(CryptoError)
end
