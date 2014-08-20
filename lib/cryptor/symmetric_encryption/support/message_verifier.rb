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

module Cryptor
  class SymmetricEncryption
    module Support
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
    end
  end
end
