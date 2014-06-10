require 'ordo'

require 'cryptor/version'
require 'cryptor/symmetric_encryption/cipher'
require 'cryptor/symmetric_encryption/keyring'
require 'cryptor/symmetric_encryption/secret_key'

module Cryptor
  # Easy-to-use authenticated symmetric encryption
  class SymmetricEncryption
    def self.random_key(cipher)
      Cipher[cipher].random_key
    end

    def initialize(active_key, options = {})
      @active_key = active_key
      @keyring    = nil

      options.each do |name, value|
        if name == :keyring
          @keyring = Keyring.new(active_key, *value)
        else fail ArgumentError, "unknown option: #{name}"
        end
      end

      @keyring ||= Keyring.new(active_key)
    end

    def encrypt(plaintext)
      ciphertext = @active_key.encrypt(plaintext)
      base64     = Base64.strict_encode64(ciphertext)

      ORDO::Message.new(
        base64,
        'Cipher'                    => @active_key.cipher.algorithm,
        'Content-Length'            => base64.bytesize,
        'Content-Transfer-Encoding' => 'base64',
        'Key-Fingerprint'           => @active_key.fingerprint
      ).to_string
    end

    def decrypt(ciphertext)
      begin
        message = ORDO::Message.parse(ciphertext)
      rescue ORDO::ParseError => ex
        raise InvalidMessageError, ex.to_s
      end

      fingerprint = message['Key-Fingerprint']
      fail InvalidMessageError, 'no key fingerprint in message' unless fingerprint

      key = @keyring[fingerprint]
      key.decrypt message.body
    end
  end
end
