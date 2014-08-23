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

require 'cryptor/symmetric_encryption/support/message_verifier'

module Cryptor
  class SymmetricEncryption
    module Support
      # MessageEncryptor class adapted from ActiveSupport
      class MessageEncryptor
        attr_reader :verifier

        def initialize(secret, sign_secret, options = {})
          @secret = secret
          @sign_secret = sign_secret
          @cipher = options[:cipher] || 'aes-256-cbc'
          @verifier = MessageVerifier.new(@sign_secret, digest: options[:digest] || 'SHA256')
        end

        def encrypt_and_sign(value)
          verifier.generate(_encrypt(value))
        end

        def verify_and_decrypt(value)
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
