require 'spec_helper'

describe Cryptor::SecretKey do
  let(:algorithm)  { :BassOmatic }
  let(:key_bytes)  { 42 }
  let(:cipher)     { Cryptor::Cipher.new(algorithm, key_bytes: key_bytes) }
  let(:secret_uri) { "secret.key:///#{algorithm};#{Cryptor::Encoding.encode("\xBA\x55")}" }

  before do
    Cryptor::Cipher.stub(:[]).and_return(cipher)
  end

  subject { described_class.new(secret_uri) }

  it 'generates random keys' do
    expect(described_class.random_key(algorithm)).to be_a described_class
  end

  it 'serializes to a URI' do
    expect(subject.to_secret_uri).to eq secret_uri
  end

  it 'raises ArgumentError if given a bogus URI' do
    expect do
      described_class.new('http://www.google.com/')
    end.to raise_exception(ArgumentError)
  end
end
