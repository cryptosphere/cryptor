require 'cryptor/version'

require 'cryptor/encoding'
require 'cryptor/secret_key'
require 'cryptor/ciphers/xsalsa20poly1305'

require 'ordo'

# An easy-to-use library for real-world Ruby cryptography
class Cryptor
  def self.random_key(cipher = :xsalsa20poly1305)
    Cipher[cipher].random_key
  end

  def initialize(key)
    @key = key
  end

  def encrypt(plaintext)
    ciphertext = @key.encrypt(plaintext)
    base64     = Base64.strict_encode64(ciphertext)

    ORDO::Message.new(
      base64,
      'Cipher'                    => @key.cipher.algorithm,
      'Content-Length'            => base64.bytesize,
      'Content-Transfer-Encoding' => 'base64',
      'Key-Fingerprint'           => @key.fingerprint
    ).to_string
  end

  def decrypt(ciphertext)
    message     = ORDO::Message.parse(ciphertext)
    fingerprint = message['Key-Fingerprint']
    encoding    = message['Content-Transfer-Encoding']

    fail ArgumentError, "invalid key fingerprint: #{fingerprint}" if @key.fingerprint != fingerprint

    case encoding
    when 'base64'
      ciphertext = Base64.strict_decode64(message.body)
    when 'binary'
      ciphertext = message.body
    else fail ArgumentError, "invalid message encoding: #{encoding}"
    end

    @key.decrypt(ciphertext)
  end
end
