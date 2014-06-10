require 'spec_helper'

# "Default" cipher used in non-backend specific tests
require 'cryptor/symmetric_encryption/ciphers/xsalsa20poly1305'

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
    require 'cryptor/symmetric_encryption/ciphers/xsalsa20poly1305'

    let(:secret_key) { described_class.random_key(:xsalsa20poly1305) }

    it 'encrypts and decrypts' do
      ciphertext = subject.encrypt(plaintext)
      expect(subject.decrypt(ciphertext)).to eq plaintext
    end

    it 'raises InvalidMessageError if asked to decrypt garbage' do
      expect { subject.decrypt(garbage) }.to raise_exception(Cryptor::InvalidMessageError)
    end

    it 'raises CorruptedMessageError if the message is corrupt' do
      valid_message  = subject.encrypt(plaintext)
      munged_message = ORDO::Message.parse(valid_message)
      munged_message.body.replace Base64.strict_encode64(munged_message.body + "\0")

      expect do
        subject.decrypt(munged_message.to_string)
      end.to raise_exception(Cryptor::CorruptedMessageError)
    end
  end

  context 'message_encryptor' do
    require 'cryptor/symmetric_encryption/ciphers/message_encryptor'

    let(:secret_key) { described_class.random_key(:message_encryptor) }

    it 'encrypts and decrypts' do
      ciphertext = subject.encrypt(plaintext)
      expect(subject.decrypt(ciphertext)).to eq plaintext
    end

    it 'raises InvalidMessageError if asked to decrypt garbage' do
      expect { subject.decrypt(garbage) }.to raise_exception(Cryptor::InvalidMessageError)
    end

    it 'raises CorruptedMessageError if the message is corrupt' do
      valid_message  = subject.encrypt(plaintext)
      munged_message = ORDO::Message.parse(valid_message)
      munged_message.body.replace Base64.strict_encode64(munged_message.body + "\0")

      expect do
        subject.decrypt(munged_message.to_string)
      end.to raise_exception(Cryptor::CorruptedMessageError)
    end
  end

  context 'key rotation' do
    let(:old_key)     { described_class.random_key(:xsalsa20poly1305) }
    let(:new_key)     { described_class.random_key(:xsalsa20poly1305) }
    let(:another_key) { described_class.random_key(:xsalsa20poly1305) }

    it 'decrypts messages under old keys' do
      old_cryptor = described_class.new(old_key, keyring: [old_key, another_key])
      message = old_cryptor.encrypt(plaintext)

      new_cryptor = described_class.new(new_key, keyring: [new_key, old_key])
      expect(new_cryptor.decrypt(message)).to eq plaintext
    end
  end
end
