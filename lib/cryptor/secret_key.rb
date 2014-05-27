require 'base64'

class Cryptor
  # Secret key used to encrypt plaintexts
  class SecretKey
    # Generate a random secret key
    #
    # @return [Cryptor::SecretKey] new secret key object
    def self.random_key(cipher)
      bytes  = RbNaCl::Random.random_bytes(cipher.key_bytes)
      base64 = Cryptor::Encoding.encode(bytes)

      new "secret.key:///#{cipher.cipher_name};#{base64}"
    end

    # Create a new SecretKey object from a URI
    #
    # @param [#to_s] uri representing a secret key
    #
    # @raise [ArgumentError] on invalid URIs
    #
    # @return [Cryptor::SecretKey] new secret key object
    def initialize(uri_string)
      uri = URI.parse(uri_string.to_s)
      fail ArgumentError, "invalid scheme: #{uri.scheme}" unless uri.scheme == 'secret.key'

      components = uri.path.match(/^\/([^;]+);(.+)$/)
      fail ArgumentError, "couldn't parse cipher name from secret URI" unless components

      @cipher = Cryptor::Cipher[components[1]].new
      @key    = Cryptor::Encoding.decode(components[2])
    end

    # Fingerprint of this key
    #
    # @return [String] fingerprint as a ni:// URL
    def fingerprint
      bytes  = RbNaCl::Hash.sha256(@key)
      base64 = Cryptor::Encoding.encode(bytes)
      "ni:///sha-256;#{base64}"
    end

    # Encrypt a plaintext under this key
    #
    # @param [String] plaintext string to be encrypted
    #
    # @return [String] ciphertext encrypted under this key
    def encrypt(plaintext)
      @cipher.encrypt(@key, plaintext)
    end

    # Decrypt ciphertext using this key
    #
    # @param [String] ciphertext string to be decrypted
    #
    # @return [String] plaintext decrypted from the given ciphertext
    def decrypt(ciphertext)
      @cipher.decrypt(@key, ciphertext)
    end

    # Inspect this key
    #
    # @return [String] a string representing this key
    def inspect
      "#<#{self.class}:0x#{object_id.to_s(16)} fingerprint=#{fingerprint}>"
    end
  end
end
