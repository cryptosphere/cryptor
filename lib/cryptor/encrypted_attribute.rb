module Cryptor
  # Support for the attr_encrypted encryptor API
  module EncryptedAttribute
    module_function

    def symmetric_encrypt(options)
      symmetric_cryptor(options).encrypt(options[:value])
    end

    def symmetric_decrypt(options)
      symmetric_cryptor(options).decrypt(options[:value])
    end

    def symmetric_cryptor(options)
      Cryptor::SymmetricEncryption.new(options[:key], keyring: options[:keyring])
    end
  end
end
