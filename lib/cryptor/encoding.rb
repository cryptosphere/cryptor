require 'base64'

class Cryptor
  # Encode and parse strings in "URL-safe" Base64 format
  module Encoding
    module_function

    # Encode a string in URL-safe Base64
    #
    # @param string [String] arbitrary string to be encoded
    # @return [String] URL-safe Base64 encoded string
    def encode(string)
      Base64.urlsafe_encode64(string)
    end

    # Decode a URL-safe Base64 string
    #
    # @param string [String] URL-safe Base64 string to be decoded
    # @return [String] decoded string
    def decode(string)
      Base64.urlsafe_decode64(string)
    end
  end
end
