require 'ordo'

require 'cryptor/version'
require 'cryptor/cipher'

module Cryptor
  # Easy-to-use authenticated symmetric encryption
  class SymmetricEncryption
    def self.random_key(cipher)
      Cipher[cipher].random_key
    end

    def initialize(key)
      @key = key
    end

    def encrypt(plaintext)
      ciphertext = @key.encrypt(plaintext)
      base64     = Base64.strict_encode64(ciphertext)

      ORDO::Message.new(
        base64,
        'Cipher'                    => @key.cipher.algorithm,
        'Content-Length'            => base64.bytesize,
        'Content-Transfer-Encoding' => 'base64',
        'Key-Fingerprint'           => @key.fingerprint
      ).to_string
    end

    def decrypt(ciphertext)
      begin
        message = ORDO::Message.parse(ciphertext)
      rescue ORDO::ParseError => ex
        fail InvalidMessageError, ex.to_s
      end

      fingerprint = message['Key-Fingerprint']
      fail ArgumentError, "no key configured for: #{fingerprint}" if @key.fingerprint != fingerprint

      @key.decrypt decode(message)
    end

    private

    def decode(message)
      encoding = message['Content-Transfer-Encoding']

      case encoding
      when 'base64' then Base64.strict_decode64(message.body)
      when 'binary' then message.body
      else fail ArgumentError, "invalid message encoding: #{encoding}"
      end
    end
  end
end
