require 'spec_helper'
require 'cryptor/symmetric_encryption/support/message_encryptor'

RSpec.describe Cryptor::SymmetricEncryption::Support::MessageEncryptor do
  let(:secret_key)   { 'X' * 32 }
  let(:verifier_key) { 'Y' * 32 }
  let(:verifier)     { Cryptor::SymmetricEncryption::Support::MessageVerifier.new(verifier_key) }
  let(:encryptor)    { described_class.new(secret_key, verifier_key) }
  let(:message)      { 'THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE' }

  it 'encrypts and decrypts data' do
    ciphertext = encryptor.encrypt_and_sign(message)
    expect(encryptor.verify_and_decrypt(ciphertext)).to eq message
  end

  it 'produces different ciphertexts when called repeatedly' do
    first_message  = encryptor.encrypt_and_sign(message).split('--')
    second_message = encryptor.encrypt_and_sign(message).split('--')
    expect(first_message).not_to eq second_message
  end

  it 'raises if ciphertext has been tampered with' do
    ciphertext, iv = encryptor.encrypt_and_sign(message).split('--')
    expect { encryptor.verify_and_decrypt("#{ciphertext.reverse}--#{iv}") }.to raise_exception
    expect { encryptor.verify_and_decrypt("#{ciphertext}--#{iv.reverse}") }.to raise_exception
    expect { encryptor.verify_and_decrypt('purejunk') }.to raise_exception
  end
end
