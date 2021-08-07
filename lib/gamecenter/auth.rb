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

    # this is a CA Code Signing certificate that can be used to verify the
    # public key certificates (which are downloaded from public_key_url)
    # converted to base64:
    # openssl x509 -inform der -in gc-prod-6.cer -out outfile.cer
    #
    # current certificate name:
    # DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 (RSA default)
    # source: https://developer.apple.com/forums/thread/686122
    # source: https://knowledge.digicert.com/alerts/code-signing-new-minimum-rsa-keysize.html
    @@ca_certificate = OpenSSL::X509::Certificate.new <<~EOCACERT
-----BEGIN CERTIFICATE-----
MIIGsDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBi
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
RzQwHhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJV
UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
dXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1
M4zrPYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZ
wZHMgQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI
8IrgnQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGi
TUyCEUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLm
ysL0p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3S
vUQakhCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tv
k2E0XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+
960IHnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3s
MJN2FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FK
PkBHX8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1H
s/q27IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAw
HQYDVR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LS
cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
BQcDAzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
cmwwHAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQAD
ggIBADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L
/Z6jfCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHV
UHmImoqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rd
KOtfJqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK
6Wrxoj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43N
b3Y3LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4Z
XDlx4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvm
oLr9Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8
y4+ICw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMM
B0ug0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+F
SCH5Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhO
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
