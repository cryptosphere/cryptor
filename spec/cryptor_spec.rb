require 'spec_helper'

describe Cryptor do
  let(:secret_key) { Cryptor.random_key }
  let(:plaintext)  { 'THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE' }

  subject { Cryptor.new(secret_key) }

  it 'encrypts and decrypts' do
    ciphertext = subject.encrypt(plaintext)
    expect(subject.decrypt(ciphertext)).to eq plaintext
  end
end
