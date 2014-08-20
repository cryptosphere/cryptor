require 'openssl'
require 'base64'

require 'cryptor/symmetric_encryption/cipher'
require 'cryptor/symmetric_encryption/support/message_encryptor'

module Cryptor
  class SymmetricEncryption
    module Ciphers
      # An authenticated encryption scheme based on AES-256-CBC and HMAC-SHA256
      # using an encrypt-then-MAC construction.
      #
      # The implementation is borrowed from ActiveSupport and is implemented
      # atop Ruby's OpenSSL extension.
      class AES256CBCHMACSHA256 < Cipher
        KEY_BYTES  = 64

        register :aes256cbchmacsha256, key_bytes: KEY_BYTES

        def encrypt(key, plaintext)
          encryptor(key).encrypt_and_sign(plaintext)
        end

        def decrypt(key, ciphertext)
          encryptor(key).decrypt_and_verify(ciphertext)
        rescue Support::MessageVerifier::InvalidSignature => ex
          raise CorruptedMessageError, ex.to_s
        end

        private

        def encryptor(key)
          fail ArgumentError, "wrong key size: #{key.bytesize}" unless key.bytesize == KEY_BYTES
          encryption_key, hmac_key = key[0, 32], key[32, 32]

          Support::MessageEncryptor.new(
            encryption_key,
            hmac_key,
            cipher: 'aes-256-cbc',
            digest: 'SHA256'
          )
        end
      end
    end
  end
end
