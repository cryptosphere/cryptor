require 'spec_helper'

describe Cryptor::SymmetricEncryption do
  let(:plaintext) { 'THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE' }

  let(:garbage) do
    'Timely and accurate information about the activities, capabilities, ' \
    'plans, and intentions of foreign powers, organizations, and persons ' \
    'and their agents, is essential to the national security of the ' \
    'United States.'
  end

  subject { described_class.new(secret_key) }

  context 'xsalsa20poly1305' do
    require 'cryptor/ciphers/xsalsa20poly1305'

    let(:secret_key) { described_class.random_key(:xsalsa20poly1305) }

    it 'encrypts and decrypts' do
      ciphertext = subject.encrypt(plaintext)
      expect(subject.decrypt(ciphertext)).to eq plaintext
    end

    it 'raises InvalidMessageError if asked to decrypt garbage' do
      expect { subject.decrypt(garbage) }.to raise_exception(Cryptor::InvalidMessageError)
    end
  end

  context 'message_encryptor' do
    require 'cryptor/ciphers/message_encryptor'

    let(:secret_key) { described_class.random_key(:message_encryptor) }

    it 'encrypts and decrypts' do
      ciphertext = subject.encrypt(plaintext)
      expect(subject.decrypt(ciphertext)).to eq plaintext
    end

    it 'raises InvalidMessageError if asked to decrypt garbage' do
      expect { subject.decrypt(garbage) }.to raise_exception(Cryptor::InvalidMessageError)
    end
  end
end
