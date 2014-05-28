class Cryptor
  # Base class of all Cryptor ciphers
  class Cipher
    REGISTRY = {}

    attr_reader :algorithm, :key_bytes

    def self.register(algorithm, options = {})
      REGISTRY[algorithm.to_s] ||= new(algorithm, options)
    end

    def self.[](algorithm)
      REGISTRY[algorithm.to_s] || fail(ArgumentError, "no such cipher: #{algorithm}")
    end

    def initialize(algorithm, options = {})
      @algorithm = algorithm
      @key_bytes = options[:key_bytes] || fail(ArgumentError, 'key_bytes not specified')
    end

    def random_key
      SecretKey.random_key(self)
    end

    def encrypt(_key, _plaintext)
      # :nocov:
      fail NotImplementedError, "'encrypt' method has not been implemented"
      # :nocov:
    end

    def decrypt(_key, _ciphertext)
      # :nocov:
      fail NotImplementedError, "'decrypt' method has not been implemented"
      # :nocov:
    end
  end
end
