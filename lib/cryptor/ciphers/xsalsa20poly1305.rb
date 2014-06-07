require 'rbnacl/libsodium'

require 'cryptor/cipher'

module Cryptor
  module Ciphers
    # XSalsa20+Poly1305 authenticated stream cipher
    class XSalsa20Poly1305 < Cipher
      register :xsalsa20poly1305, key_bytes: RbNaCl::SecretBoxes::XSalsa20Poly1305.key_bytes

      def encrypt(key, plaintext)
        box(key).encrypt(plaintext)
      end

      def decrypt(key, ciphertext)
        box(key).decrypt(ciphertext)
      rescue RbNaCl::CryptoError => ex
        raise CorruptedMessageError, ex.to_s
      end

      private

      def box(key)
        RbNaCl::SimpleBox.new(RbNaCl::SecretBoxes::XSalsa20Poly1305.new(key))
      end
    end
  end
end
