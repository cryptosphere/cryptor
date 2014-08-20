# An authenticated encryption implementation based on ActiveSupport's
# MessageEncryptor, which is vendored for your convenience.
#
# The implementation has been tweaked to better conform with
# JSON Web Encryption standards.
#
# The following copyright notice is included verbatim from Activesupport,
# but I'd just like to point out the fact that DHH had absolutely nothing
# to do with this code, which given it's dealing with cryptography,
# is probably a good thing.
#
# Copyright (c) 2005-2014 David Heinemeier Hansson
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'openssl'
require 'base64'

require 'cryptor/symmetric_encryption/cipher'

module Cryptor
  class SymmetricEncryption
    module Ciphers
      # An authenticated encryption scheme based on AES-256-CBC and HMAC-SHA256
      # using an encrypt-then-MAC construction.
      #
      # The implementation is borrowed from ActiveSupport and is implemented
      # atop Ruby's OpenSSL extension.
      class AES256CBCHMACSHA256 < Cipher
        KEY_BYTES  = 64

        register :aes256cbchmacsha256, key_bytes: KEY_BYTES

        def encrypt(key, plaintext)
          encryptor(key).encrypt_and_sign(plaintext)
        end

        def decrypt(key, ciphertext)
          encryptor(key).decrypt_and_verify(ciphertext)
        rescue MessageVerifier::InvalidSignature => ex
          raise CorruptedMessageError, ex.to_s
        end

        private

        def encryptor(key)
          fail ArgumentError, "wrong key size: #{key.bytesize}" unless key.bytesize == KEY_BYTES
          encryption_key, hmac_key = key[0, 32], key[32, 32]
          MessageEncryptor.new(encryption_key, hmac_key)
        end

        # MessageVerifier class adapted from ActiveSupport
        class MessageVerifier
          class InvalidSignature < StandardError; end

          def initialize(secret, options = {})
            @secret = secret
            @digest = options[:digest] || 'SHA256'
          end

          def verify(signed_message)
            fail InvalidSignature if signed_message.empty?

            data, digest = signed_message.split('--')
            if data && digest && secure_compare(digest, generate_digest(data))
              ::Base64.strict_decode64(data)
            else
              fail InvalidSignature
            end
          end

          def generate(value)
            data = ::Base64.strict_encode64(value)
            "#{data}--#{generate_digest(data)}"
          end

          private

          # constant-time comparison algorithm to prevent timing attacks
          def secure_compare(a, b)
            return false unless a.bytesize == b.bytesize

            l = a.unpack "C#{a.bytesize}"

            res = 0
            b.each_byte { |byte| res |= byte ^ l.shift }
            res == 0
          end

          def generate_digest(data)
            require 'openssl' unless defined?(OpenSSL)
            OpenSSL::HMAC.hexdigest(OpenSSL::Digest.const_get(@digest).new, @secret, data)
          end
        end

        # MessageEncryptor class adapted from ActiveSupport
        class MessageEncryptor
          attr_reader :verifier

          def initialize(secret, sign_secret, options = {})
            @secret = secret
            @sign_secret = sign_secret
            @cipher = options[:cipher] || 'aes-256-cbc'
            @verifier = MessageVerifier.new(@sign_secret)
          end

          def encrypt_and_sign(value)
            verifier.generate(_encrypt(value))
          end

          def decrypt_and_verify(value)
            _decrypt(verifier.verify(value))
          end

          private

          def _encrypt(value)
            cipher = new_cipher
            cipher.encrypt
            cipher.key = @secret

            iv = cipher.random_iv

            encrypted_data = cipher.update(value)
            encrypted_data << cipher.final

            "#{::Base64.strict_encode64 encrypted_data}--#{::Base64.strict_encode64 iv}"
          end

          def _decrypt(encrypted_message)
            cipher = new_cipher
            ciphertext, iv = encrypted_message.split('--').map { |v| ::Base64.strict_decode64(v) }

            cipher.decrypt
            cipher.key = @secret
            cipher.iv  = iv

            decrypted_data = cipher.update(ciphertext)
            decrypted_data << cipher.final

            decrypted_data
          rescue OpenSSLCipherError, TypeError, ArgumentError
            raise InvalidMessage
          end

          def new_cipher
            OpenSSL::Cipher::Cipher.new(@cipher)
          end
        end
      end
    end
  end
end
