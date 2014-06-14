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
      @active_key = active_key.is_a?(SecretKey) ? active_key : SecretKey.new(active_key)
      @keyring    = nil

      options.each do |name, value|
        if name == :keyring
          @keyring = Keyring.new(@active_key, *value)
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
      message = parse(ciphertext)
      fingerprint = message['Key-Fingerprint']
      fail InvalidMessageError, 'no key fingerprint in message' unless fingerprint

      key = @keyring[fingerprint]
      key.decrypt message.body
    end

    def rotate!(ciphertext)
      message = parse(ciphertext)
      fingerprint = message['Key-Fingerprint']
      fail AlreadyRotatedError, 'already current' if fingerprint == @active_key.fingerprint

      key = @keyring[fingerprint]
      encrypt(key.decrypt(message.body))
    end

    def rotate(ciphertext)
      rotate!(ciphertext)
    rescue AlreadyRotatedError
      ciphertext
    end

    private

    def parse(message)
      ORDO::Message.parse(message)
    rescue ORDO::ParseError => ex
      raise InvalidMessageError, ex.to_s
    end
  end
end
