require 'gamecenter/auth/version'
require 'uri'
require 'logger'
require 'base64'

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

    @@ca_certificate = OpenSSL::X509::Certificate.new <<EOCACERT
-----BEGIN CERTIFICATE-----
MIIFWTCCBEGgAwIBAgIQPXjX+XZJYLJhffTwHsqGKjANBgkqhkiG9w0BAQsFADCB
yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW
ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5IC0gRzUwHhcNMTMxMjEwMDAwMDAwWhcNMjMxMjA5MjM1OTU5WjB/MQsw
CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNV
BAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMDAuBgNVBAMTJ1N5bWFudGVjIENs
YXNzIDMgU0hBMjU2IENvZGUgU2lnbmluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAJeDHgAWryyx0gjE12iTUWAecfbiR7TbWE0jYmq0v1obUfej
DRh3aLvYNqsvIVDanvPnXydOC8KXyAlwk6naXA1OpA2RoLTsFM6RclQuzqPbROlS
Gz9BPMpK5KrA6DmrU8wh0MzPf5vmwsxYaoIV7j02zxzFlwckjvF7vjEtPW7ctZlC
n0thlV8ccO4XfduL5WGJeMdoG68ReBqYrsRVR1PZszLWoQ5GQMWXkorRU6eZW4U1
V9Pqk2JhIArHMHckEU1ig7a6e2iCMe5lyt/51Y2yNdyMK29qclxghJzyDJRewFZS
AEjM0/ilfd4v1xPkOKiE1Ua4E4bCG53qWjjdm9sCAwEAAaOCAYMwggF/MC8GCCsG
AQUFBwEBBCMwITAfBggrBgEFBQcwAYYTaHR0cDovL3MyLnN5bWNiLmNvbTASBgNV
HRMBAf8ECDAGAQH/AgEAMGwGA1UdIARlMGMwYQYLYIZIAYb4RQEHFwMwUjAmBggr
BgEFBQcCARYaaHR0cDovL3d3dy5zeW1hdXRoLmNvbS9jcHMwKAYIKwYBBQUHAgIw
HBoaaHR0cDovL3d3dy5zeW1hdXRoLmNvbS9ycGEwMAYDVR0fBCkwJzAloCOgIYYf
aHR0cDovL3MxLnN5bWNiLmNvbS9wY2EzLWc1LmNybDAdBgNVHSUEFjAUBggrBgEF
BQcDAgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgEGMCkGA1UdEQQiMCCkHjAcMRow
GAYDVQQDExFTeW1hbnRlY1BLSS0xLTU2NzAdBgNVHQ4EFgQUljtT8Hkzl699g+8u
K8zKt4YecmYwHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJKoZI
hvcNAQELBQADggEBABOFGh5pqTf3oL2kr34dYVP+nYxeDKZ1HngXI9397BoDVTn7
cZXHZVqnjjDSRFph23Bv2iEFwi5zuknx0ZP+XcnNXgPgiZ4/dB7X9ziLqdbPuzUv
M1ioklbRyE07guZ5hBb8KLCxR/Mdoj7uh9mmf6RWpT+thC4p3ny8qKqjPQQB6rqT
og5QIikXTIfkOhFf1qQliZsFay+0yQFMJ3sLrBkFIqBgFT/ayftNTI/7cmd3/SeU
x7o1DohJ/o39KK9KEr0Ns5cF3kQMFfo2KwPcwVAB8aERXRTl4r0nS1S+K4ReD6bD
dAUK75fDiSKxH3fzvc1D1PFMqT+1i4SvZPLQFCE=
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

    # Verifies that the public key url originates from one of Apple's secured servers
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

    # Checks if given public key certificate can be verified with the CA certificate
    # @param [OpenSSL::X509::Certificate] public_key_cert a previously fetched public key certificate object
    # @return [Boolean] true if certificate could be verified against the CA certificate, false if it couldn't
    def verify_public_key_certificate(public_key_cert)
      verified = public_key_cert.verify(@@ca_certificate.public_key)
      no_errors = OpenSSL.errors.empty? # this method has to be called always as it empties the OpenSSL error stack

      verified && no_errors
    end

    # Verifies the signature of given payload with given public key certificate
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
