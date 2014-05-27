class Cryptor
  # Base class of all Cryptor ciphers
  class Cipher
    REGISTRY = {}

    class << self
      attr_reader :cipher_name, :key_bytes
    end

    def self.register(name, options = {})
      REGISTRY[name.to_s] ||= self

      @cipher_name = name
      @key_bytes   = options[:key_bytes] || fail(ArgumentError, 'key_bytes not specified')
    end

    def self.[](name)
      REGISTRY[name.to_s] || fail(ArgumentError, "no such cipher: #{name}")
    end

    def self.random_key
      SecretKey.random_key(self)
    end

    def encrypt(_key, _plaintext)
      fail NotImplementedError, "'encrypt' method has not been implemented"
    end

    def decrypt(_key, _ciphertext)
      fail NotImplementedError, "'decrypt' method has not been implemented"
    end
  end
end
