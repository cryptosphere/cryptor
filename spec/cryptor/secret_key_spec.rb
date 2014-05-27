require 'spec_helper'

describe Cryptor::SecretKey do
  let(:cipher_class) { double(:cipher_class) }
  let(:cipher_inst)  { double(:cipher_inst) }

  it 'generates random keys' do
    Cryptor::Cipher.stub(:[]).and_return(cipher_class)

    cipher_class.should_receive(:key_bytes).and_return(42)
    cipher_class.should_receive(:cipher_name).and_return(:vogon)
    cipher_class.should_receive(:new).and_return(cipher_inst)

    expect(described_class.random_key(cipher_class)).to be_a described_class
  end

  it 'raises ArgumentError if given a bogus URI' do
    expect do
      described_class.new('http://www.google.com/')
    end.to raise_exception(ArgumentError)
  end
end
