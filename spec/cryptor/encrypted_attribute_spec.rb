require 'spec_helper'

# "Default" cipher used in non-backend specific tests
require 'cryptor/symmetric_encryption/ciphers/xsalsa20poly1305'

RSpec.describe Cryptor::EncryptedAttribute do
  let(:plaintext)  { 'THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE' }
  let(:secret_key) { Cryptor::SymmetricEncryption.random_key(:xsalsa20poly1305) }

  context 'symmetric encryption' do
    it 'encrypts and decrypts' do
      ciphertext = described_class.symmetric_encrypt(key: secret_key, value: plaintext)
      expect(described_class.symmetric_decrypt(key: secret_key, value: ciphertext)).to eq plaintext
    end
  end
end
