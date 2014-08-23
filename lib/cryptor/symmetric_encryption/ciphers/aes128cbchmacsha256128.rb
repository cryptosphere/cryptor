require 'cryptor/symmetric_encryption/ciphers/aescbchmacsha2'

module Cryptor
  class SymmetricEncryption
    module Ciphers
      # A concrete implementation of the generic AES_CBC_HMAC_SHA2 algorithm
      # using the HMAC message authentication code [RFC2104] with the SHA-256
      # hash function [SHS] to provide message authentication, with the HMAC
      # output truncated to 128 bits, corresponding to the HMAC-SHA-256-128
      # algorithm defined in [RFC4868].
      #
      # For encryption, it uses AES in the Cipher Block Chaining (CBC) mode
      # of operation as defined in Section 6.2 of [NIST.800-38A], with PKCS#7
      # padding and a 128 bit initialization vector (IV) value.
      class AES128CBCHMACSHA256128 < AESCBCHMACSHA2
        # Number of bytes in a key for this cipher
        def self.key_bytes
          64
        end

        # Name of the cipher as implemented by OpenSSL
        def self.ossl_cipher
          'aes-256-cbc'
        end

        # Name of the digest as implemented by OpenSSL
        def self.ossl_digest
          'SHA256'
        end

        register :aes128cbchmacsha256128, key_bytes: key_bytes
      end
    end
  end
end
