require 'gamecenter/auth/version'
require 'uri'
require 'logger'
require 'base64'
require 'openssl'

module Gamecenter
  class Auth

    @@verify_issuer_certificate = true

    @@cache_public_keys = true
    @@public_key_cache_entries = 10 # 1+: cache this many public keys (has to be 1 at least!)

    @@base64_decode_salt = true
    @@base64_decode_signature = true

    @@request_public_key_open_timeout = 5 # seconds
    @@request_public_key_read_timeout = 5 # seconds
    @@request_public_key_ssl_timeout = 5 # seconds

    @@ca_certificate = OpenSSL::X509::Certificate.new <<~EOCACERT
      -----BEGIN CERTIFICATE-----
      MIIHbDCCBVSgAwIBAgIQAwuBj1pc45FkhpmTbIvZOjANBgkqhkiG9w0BAQsFADBp
      MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
      OERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0
      IDIwMjEgQ0ExMB4XDTIxMDcyOTAwMDAwMFoXDTIyMDcyODIzNTk1OVowcTELMAkG
      A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCUN1cGVydGlu
      bzETMBEGA1UEChMKQXBwbGUgSW5jLjEPMA0GA1UECxMGR0MgU1JFMRMwEQYDVQQD
      EwpBcHBsZSBJbmMuMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyGXC
      hfNKtSFUkayI4RGDl1T7cTqs9Ni6vnwJpU/9nTT3BWWxZ2Yng4muIhMeA3oZfDZu
      T1ShS5y3CQV9/9SaUU1NNfnPxenvrrE8xSn8a9bo2adTrn9ASrEMqRD6bp+fS5Cp
      kFHYH+VD5a8XTyOuDGpQyqIpUpYqGABXITWrEpjnpAw1IjMaeNO9sYJkWuLdw0gg
      IMpBqmiiJXHgasl8D59S93PVHD1xkEjZcPT9NEWJXSRHUW+Xe+JUhrFSzEfjyWNS
      spgJrnVtv4ec30Uz0qUC683lkfE446VPiIyo3xmjh3rs3G75JYJd5925YVM0uz1U
      Wn0VmOTN5s81V6CBdYRc3J0sCGd5QEmDo4pwPwCMej+fT6fktIXUWZ1i/ycI1//m
      Vc4kkuyiJ2msv8GSACPG6XkL+zKTjYC+GElj/WCX+hVJKzsYtL51zRr4KNnqhG7/
      GK5kJ9eVTgTEKqdB0DZ7ZpOD3EoE2D9kj4zaoq/7r6Syi7Efw230zDMQyIJnoUQc
      GDWUR2ZPQ+U+aUOKdWpgbhy4vOzTi24hOVcACbvc/CFTQ2gI7SfCSao9WLVqqGO5
      waHhoOidTYY9Ey2PQvYHqXm5R2Ol+3V+GQl0NkiDt5kc7OpYIm7cDyQ04ZaHnUDt
      ZljI5N1fdlhYVKntEzX4sNhcx1pNB1C/T5Wfw68CAwEAAaOCAgYwggICMB8GA1Ud
      IwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBRS7TCGHb7iPnHR
      /odXPWLpAxPVKjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
      gbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
      Z2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5j
      cmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
      ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMD4GA1UdIAQ3
      MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQu
      Y29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
      Y3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2VydHMuZGln
      aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hB
      Mzg0MjAyMUNBMS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEA
      uk71YLf55ne94hEeQtYsjCn38Tw3h78CH195J8H4T4r2p7p9MPjrA2zz+ZXza+kb
      z5OTZ9k1/nu9vKnh4ljZS33uTh5AcdWhQNUeSuByjhVu+YTnVKqVYH/jaZXEFFe/
      4/n23Shn2xN5jtkCEwYeqEaO6+8uBCFQldnUgbSag2Le9s/lICUJvGsKTAUhEGrK
      R4u4OyJGGk8JO5Ozbnoe1AGBK9pKMWOAl+SY/b/CLLTgypwZwD/6xszM1MhcfzPS
      aBbJ7MX2Uiq91/PNJdPnZI/PoqAQEzDL+5MZnwKwNpeC1rH8ZhlCn1BXbxI5jemw
      Tfo2U6cDN1ObJ4LBzsVioWA0KoNnp4eWkMmbGGH5iWRcwoCjhkzot8VvXoll0uSe
      F9v1RMOCM+Vcr++MYdJxdoQDNMunEoUnpHQbreHSLMcwPUhSNO4+EtZA86hob2u0
      6yMXdAi9pEs9Aj13LAW74MCDrToCzoa2ZaisvxbRfQSpXryUQEnqpuQqCVjglxaJ
      FIMhV0DRWIaLF9vhv6zF9kL77qr+arLd/wJlXubtD/P9tJZRlEh6/0iHvyyH2+Rg
      u05//UQ7ex/j15PLFSVkQXIFPpN1ZgN0FrJKAJOL+MWiB5RncKxjin8Y9xfC3XKS
      fbV6c7J9AGi8bE8aFMM2ISg7v/dOQzcLPPScWbe5cTg=
      -----END CERTIFICATE-----
    EOCACERT

    # Verifies the identity of the given player. Takes all return values from GameKit's generateIdentityVerificationSignatureWithCompletionHandler method.
    # @see https://developer.apple.com/library/prerelease/ios/documentation/GameKit/Reference/GKLocalPlayer_Ref/index.html#//apple_ref/occ/instm/GKLocalPlayer/generateIdentityVerificationSignatureWithCompletionHandler:
    # @param [String] player_id the playerID from the player to verify identity of
    # @param [String] bundle_id the app's bundleID
    # @param [String] public_key_url the publicKeyURL property returned from the GameKit framework
    # @param [String] signature the signature property returned from the GameKit framework
    # @param [String] salt the salt property returned from the GameKit framework
    # @param [Integer] timestamp the timestamp property returned from the GameKit framework
    # @return [Boolean] true if player could be verified, false if not
    def verify_player(player_id, bundle_id, public_key_url, signature, salt, timestamp)
      unless verify_public_key_url public_key_url
        logger.debug { "public key url invalid: #{public_key_url}" }
        return false
      end

      cert = get_public_key_certificate public_key_url
      unless cert
        logger.debug { "could not get certificate from: #{public_key_url}" }
        return false
      end
      if @@verify_issuer_certificate && !verify_public_key_certificate(cert)
        logger.debug { "failed verification of public key certificate from: #{public_key_url}" }
        return false
      end

      salt_decoded = @@base64_decode_salt ? Base64.decode64(salt) : salt
      payload = "#{player_id}#{bundle_id}#{[timestamp.to_i].pack('Q>')}#{salt_decoded}"
      signature_decoded = @@base64_decode_signature ? Base64.decode64(signature) : signature
      unless verify_signature cert, signature_decoded, payload
        logger.debug { "failed signature validation for player id #{player_id}, bundle id #{bundle_id}, timestamp #{timestamp}, salt #{salt} (decode: #{@@base64_decode_salt}), signature #{signature} (decode: #{@@base64_decode_signature}) with certificate from: #{public_key_url}" }
        return false
      end

      true
    end

    # Verifies that the public key url originates from one of Apple's secured servers.
    # @param [String] public_key_url The publicKeyURL property returned from the GameKit framework
    # @return [Boolean] true if url verification was successful, false if url fails verification
    def verify_public_key_url(public_key_url)
      url_ok = false
      begin
        uri = URI.parse public_key_url
        url_ok = uri.scheme == 'https' && !!(uri.host =~ /\.apple\.com$/i)
      rescue URI::InvalidURIError => e
        logger.error e
      end

      url_ok
    end

    # Checks if given public key certificate can be verified with the CA certificate.
    # @param [OpenSSL::X509::Certificate] public_key_cert a previously fetched public key certificate object
    # @return [Boolean] true if certificate could be verified against the CA certificate, false if it couldn't
    def verify_public_key_certificate(public_key_cert)
      verified = public_key_cert.verify(@@ca_certificate.public_key)
      no_errors = OpenSSL.errors.empty? # this method has to be called always as it empties the OpenSSL error stack

      verified && no_errors
    end

    # Verifies the signature of given payload with given public key certificate.
    # @param [OpenSSL:X509::Certificate] public_key_cert a previously fetched public key certificate object
    # @param [String] signature the signature to be verified
    # @param [String] payload the payload to verify the signature for
    # @return [Boolean] true if signature is valid for given certificate and payload, false if it isn't
    def verify_signature(public_key_cert, signature, payload)
      verified = public_key_cert.public_key.verify(OpenSSL::Digest::SHA256.new, signature, payload)
      no_errors = OpenSSL.errors.empty? # this method has to be called always as it empties the OpenSSL error stack

      verified && no_errors
    end

    # Get a public key certificate for given URL. Caches the results, depending on the configuration.
    # @param [String] public_key_url the URL of the certificate to fetch
    # @return [OpenSSL::X509::Certificate] certificate found at given URL or nil if there was an error
    def get_public_key_certificate(public_key_url)
      if @@cache_public_keys
        # caching is enabled
        cache = (@@_public_key_cache ||= {})
        cert = cache[public_key_url]
        unless cert && cert.not_after > Time.now
          # no cache hit or certificate expired
          cache.delete public_key_url

          cert = request_public_key_certificate public_key_url

          available_entries = @@public_key_cache_entries - cache.size
          # check if there are free entries
          unless available_entries > 0
            # there are not, randomly delete enough to make room for this certificate
            cache.keys.sample(available_entries.abs + 1).each { |key|
              cache.delete key
            }
          end
          cache[public_key_url] = cert
        end

        cert
      else
        # caching is disabled
        request_public_key_certificate public_key_url
      end
    end

    # Fetch a certificate from given URL.
    # @param [String] public_key_url the URL to fetch the certificate from
    # @return [OpenSSL::X509::Certificate] certificate found at given URL or nil if there was an error
    def request_public_key_certificate(public_key_url)
      uri = URI.parse public_key_url
      begin
        Net::HTTP.start(uri.host, uri.port,
                        use_ssl: uri.scheme == 'https',
                        open_timeout: @@request_public_key_open_timeout,
                        read_timeout: @@request_public_key_read_timeout,
                        ssl_timeout: @@request_public_key_ssl_timeout) do |http|
          request = Net::HTTP::Get.new uri.request_uri
          response = http.request request # Net::HTTPResponse object
          begin
            return OpenSSL::X509::Certificate.new(response.body) if response.body
          rescue OpenSSL::X509::CertificateError => e
            logger.error e
          end
        end
      rescue Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError => e
        logger.error e
      end

      nil
    end

    private

    def logger
      @@logger ||= Logger.new(STDERR)
    end

  end
end
