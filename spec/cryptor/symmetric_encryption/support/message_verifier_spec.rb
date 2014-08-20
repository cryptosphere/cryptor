require 'spec_helper'
require 'cryptor/symmetric_encryption/support/message_verifier'

RSpec.describe Cryptor::SymmetricEncryption::Support::MessageVerifier do
  let(:message) { 'THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE' }

  subject { described_class.new('Hey, this is a secret!') }

  it 'round trips data' do
    signed_message = subject.generate(message)
    expect(subject.verify(signed_message)).to eq message
  end

  it 'raises if signature missing' do
    expect { subject.verify(nil) }.to raise_exception
    expect { subject.verify('') }.to raise_exception
  end

  it 'raises if data has been tampered with' do
    data, hash = subject.generate(message).split('--')
    expect { subject.verify("#{data.reverse}--#{hash}") }.to raise_exception
    expect { subject.verify("#{data}--#{hash.reverse}") }.to raise_exception
    expect { subject.verify('purejunk') }.to raise_exception
  end
end
