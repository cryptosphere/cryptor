require 'base64'
require 'digest/sha2'

class Cryptor
  # Secret key used to encrypt plaintexts
  class SecretKey
    # Generate a random secret key
    #
    # @param [Cryptor::Cipher, Symbol] Cryptor::Cipher or algorithm name as a symbol
    #
    # @return [Cryptor::SecretKey] new secret key object
    def self.random_key(cipher)
      cipher = Cryptor::Cipher[cipher] if cipher.is_a? Symbol
      fail ArgumentError, "invalid cipher: #{cipher.inspect}" unless cipher.is_a? Cryptor::Cipher
      bytes  = RbNaCl::Random.random_bytes(cipher.key_bytes)
      base64 = Cryptor::Encoding.encode(bytes)

      new "secret.key:///#{cipher.algorithm};#{base64}"
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

      @cipher     = Cryptor::Cipher[components[1]]
      @secret_key = Cryptor::Encoding.decode(components[2])
    end

    # Serialize SecretKey object to a URI
    #
    # @return [String] serialized URI representing the key
    def to_secret_uri
      "secret.key:///#{@cipher.algorithm};#{Cryptor::Encoding.encode(@secret_key)}"
    end

    # Fingerprint of this key's secret URI
    #
    # @return [String] fingerprint as a ni:// URL
    def fingerprint
      digest = Digest::SHA256.digest(to_secret_uri)
      "ni:///sha-256;#{Cryptor::Encoding.encode(digest)}"
    end

    # Encrypt a plaintext under this key
    #
    # @param [String] plaintext string to be encrypted
    #
    # @return [String] ciphertext encrypted under this key
    def encrypt(plaintext)
      @cipher.encrypt(@secret_key, plaintext)
    end

    # Decrypt ciphertext using this key
    #
    # @param [String] ciphertext string to be decrypted
    #
    # @return [String] plaintext decrypted from the given ciphertext
    def decrypt(ciphertext)
      @cipher.decrypt(@secret_key, ciphertext)
    end

    # Inspect this key
    #
    # @return [String] a string representing this key
    def inspect
      "#<#{self.class}:0x#{object_id.to_s(16)} fingerprint=#{fingerprint}>"
    end
  end
end
