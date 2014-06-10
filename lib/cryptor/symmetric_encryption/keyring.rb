require 'cryptor/symmetric_encryption/secret_key'

module Cryptor
  class SymmetricEncryption
    # Stores multiple keys for the purposes of key rotation
    class Keyring
      def initialize(*keys)
        @keys = {}
        keys.each do |key|
          key = SecretKey.new(key) if key.is_a? String
          fail TypeError, "not a valid secret key: #{key.inspect}" unless key.is_a? SecretKey
          @keys[key.fingerprint] = key
        end
      end

      def find(fingerprint)
        @keys[fingerprint] || fail(KeyNotFoundError, "no key for fingerprint: #{fingerprint}")
      end
      alias_method :[], :find
    end
  end
end
