require 'active_support/message_encryptor'
require 'active_support/message_verifier'

require 'cryptor/symmetric_encryption/cipher'

module Cryptor
  module Ciphers
    # MessageEncryptor is a bespoke authenticated encryption scheme invented
    # by rails-core. It uses AES-256-CBC and HMAC-SHA1 in an encrypt-then-MAC
    # scheme with a wacky and wild semiconstant-time MAC comparison.

    # Cryptor enforces the usage of independent keys for AES encryption and HMAC
    # by mandating a 64-byte key (using 32-bytes for AES and 32-bytes for HMAC).
    #
    # This scheme is probably safe to use, but less interoperable and more
    # poorly designed than xsalsa20poly1305 from RbNaCl. It does, however,
    # work using only ActiveSupport and the Ruby OpenSSL extension as
    # dependencies, and should be available anywhere.
    #
    # For the time being, this scheme is only supported for ActiveSupport 4.0+
    # although support for earlier versions of ActiveSupport should be
    # possible.
    class MessageEncryptor < Cipher
      SERIALIZER = ActiveSupport::MessageEncryptor::NullSerializer
      KEY_BYTES  = 64

      register :message_encryptor, key_bytes: KEY_BYTES

      def encrypt(key, plaintext)
        encryptor(key).encrypt_and_sign(plaintext)
      end

      def decrypt(key, ciphertext)
        encryptor(key).decrypt_and_verify(ciphertext)
      rescue ActiveSupport::MessageVerifier::InvalidSignature => ex
        raise CorruptedMessageError, ex.to_s
      end

      private

      def encryptor(key)
        fail ArgumentError, "wrong key size: #{key.bytesize}" unless key.bytesize == KEY_BYTES
        encryption_key, hmac_key = key[0, 32], key[32, 32]
        ActiveSupport::MessageEncryptor.new(encryption_key, hmac_key, serializer: SERIALIZER)
      end
    end
  end
end
