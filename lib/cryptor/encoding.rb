require 'base64'

module Cryptor
  # Encode and parse strings in "URL-safe" Base64 format
  module Encoding
    module_function

    # Encode a string in unpadded URL-safe Base64
    #
    # @param string [String] arbitrary string to be encoded
    # @return [String] URL-safe Base64 encoded string (sans '=' padding)
    def encode(string)
      Base64.urlsafe_encode64(string).sub(/=*$/, '')
    end

    # Decode an unpadded URL-safe Base64 string
    #
    # @param string [String] URL-safe Base64 string to be decoded (sans '=' padding)
    # @return [String] decoded string
    def decode(string)
      padding_size  = string.bytesize % 4
      padded_string =  padding_size > 0 ? string + '=' * (4 - padding_size) : string

      Base64.urlsafe_decode64(padded_string)
    end
  end
end
