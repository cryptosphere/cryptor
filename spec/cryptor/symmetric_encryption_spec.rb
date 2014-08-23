require 'spec_helper'

# "Default" cipher used in non-backend specific tests
require 'cryptor/symmetric_encryption/ciphers/xsalsa20poly1305'

RSpec.describe Cryptor::SymmetricEncryption do
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

  context 'aes128cbchmacsha256128' do
    require 'cryptor/symmetric_encryption/ciphers/aes128cbchmacsha256128'

    let(:secret_key) { described_class.random_key(:aes128cbchmacsha256128) }

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

    it 'rotates messages encrypted under old keys to the active key' do
      old_cryptor = described_class.new(old_key, keyring: [old_key, another_key])
      old_message = old_cryptor.encrypt(plaintext)

      hybrid_cryptor = described_class.new(new_key, keyring: [new_key, old_key])
      new_message = hybrid_cryptor.rotate(old_message)

      new_cryptor = described_class.new(new_key)
      expect(new_cryptor.decrypt(new_message)).to eq plaintext
    end

    it 'raises AlreadyRotatedError on up-to-date messages if called with a bang' do
      cryptor = described_class.new(new_key)
      message = cryptor.encrypt(plaintext)

      expect { cryptor.rotate!(message) }.to raise_exception(Cryptor::AlreadyRotatedError)
    end
  end
end
