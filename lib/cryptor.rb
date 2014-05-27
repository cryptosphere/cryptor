require 'cryptor/version'

require 'cryptor/encoding'
require 'cryptor/secret_key'
require 'cryptor/ciphers/xsalsa20poly1305'

require 'forwardable'

# An easy-to-use library for real-world Ruby cryptography
class Cryptor
  extend Forwardable
  def_delegators :@key, :encrypt, :decrypt

  def self.random_key(cipher = :xsalsa20poly1305)
    Cipher[cipher].random_key
  end

  def initialize(key)
    @key = key
  end
end
