require 'cryptor/symmetric_encryption/cipher'
require 'cryptor/symmetric_encryption/support/message_encryptor'

module Cryptor
  class SymmetricEncryption
    module Ciphers
      # A family of authenticated encryption algorithms built using a
      # composition of Advanced Encryption Standard (AES) in Cipher Block
      # Chaining (CBC) mode with PKCS #7 padding [AES,NIST.800-38A] operations
      # and HMAC [RFC2104, SHS] operations.
      #
      # These algorithms are based upon Authenticated Encryption with AES-CBC
      # and HMAC-SHA [I-D.mcgrew-aead-aes-cbc-hmac-sha2], performing the same
      # cryptographic computations, but with the Initialization Vector and
      # Authentication Tag values remaining separate, rather than being
      # concatenated with the Ciphertext value in the output representation.
      class AESCBCHMACSHA2 < Cipher
        def encrypt(key, plaintext)
          encryptor(key).encrypt_and_sign(plaintext)
        end

        def decrypt(key, ciphertext)
          encryptor(key).verify_and_decrypt(ciphertext)
        rescue Support::MessageVerifier::InvalidSignature => ex
          raise CorruptedMessageError, ex.to_s
        end

        private

        def encryptor(key)
          if key.bytesize != self.class.key_bytes
            fail ArgumentError, "wrong key size: #{key.bytesize}"
          end

          encryption_key, hmac_key = key[0, 32], key[32, 32]

          Support::MessageEncryptor.new(
            encryption_key,
            hmac_key,
            cipher: self.class.ossl_cipher,
            digest: self.class.ossl_digest
          )
        end
      end
    end
  end
end
