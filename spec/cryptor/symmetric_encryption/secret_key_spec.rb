require 'spec_helper'

RSpec.describe Cryptor::SymmetricEncryption::SecretKey do
  let(:algorithm)  { :BassOmatic }
  let(:key_bytes)  { 42 }
  let(:cipher)     { Cryptor::SymmetricEncryption::Cipher.new(algorithm, key_bytes: key_bytes) }
  let(:secret_key) { "\xBA\x55" }
  let(:secret_uri) { "secret.key:///#{algorithm};#{Cryptor::Encoding.encode(secret_key)}" }

  before do
    allow(Cryptor::SymmetricEncryption::Cipher).to receive(:[]).and_return(cipher)
  end

  subject { described_class.new(secret_uri) }

  it 'generates random keys' do
    expect(described_class.random_key(algorithm)).to be_a described_class
  end

  it 'serializes to a URI' do
    expect(subject.to_secret_uri).to eq secret_uri
  end

  it 'serializes to a key fingerprint' do
    expect(URI(subject.fingerprint).scheme).to eq 'ni'
  end

  it 'inspects without revealing the secret key' do
    expect(subject.inspect).not_to include(secret_key)
    expect(subject.inspect).not_to include(Cryptor::Encoding.encode(secret_key))
  end

  it 'raises ArgumentError if given a bogus URI' do
    expect do
      described_class.new('http://www.google.com/')
    end.to raise_exception(ArgumentError)
  end
end
