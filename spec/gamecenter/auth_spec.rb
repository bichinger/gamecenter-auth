require 'spec_helper'

describe Gamecenter::Auth do
  before :each do
    @player_id = 'G:123148854'
    @bundle_id = 'de.bichinger.test.gamekit-auth'
    @public_key_url = 'https://static.gc.apple.com/public-key/gc-prod-2.cer'
    @signature = 'SGKgszgKffUshV4aMe0aQHAvzSointPjBlfF2MK34gHY50DycZlC5gwKDpRb+gBCS2OHQNLSRctYV5WORYsDbjAcNdrzR2Tl0oDMptpBiVJQX+kCilv45Fbs7szEJ2jw/4Xl/CAFlX/HtRxYZKb4oeC/knB5ueuDGcAyjFZJkl8FmFvyRn2ZeO0pGfefzQ2lz3bgHkwgcY+w8ZMQ5wIoHkgt4x44H21hnI5he/G0q48Il0lc3frWiojeZn2UWIo8j601svFHSDkX3mx9SJrYeP4f8goJ8ax1/fVVHxSdh2+uKW+9Zz/gAbrAC4xtVUiz12DjHZf9G6hxZ0etrjZYBQ=='
    @salt = 'Yt1c3Q=='
    @timestamp = 1445940012818

    @cert = OpenSSL::X509::Certificate.new <<EOCERT
-----BEGIN CERTIFICATE-----
MIIE5zCCA8+gAwIBAgIQcU4aaTvnLkE8FjMzAtRKZTANBgkqhkiG9w0BAQsFADB/
MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAd
BgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMDAuBgNVBAMTJ1N5bWFudGVj
IENsYXNzIDMgU0hBMjU2IENvZGUgU2lnbmluZyBDQTAeFw0xNTAyMjgwMDAwMDBa
Fw0xNzAyMjcyMzU5NTlaMG4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAG
A1UEBwwJQ3VwZXJ0aW5vMRMwEQYDVQQKDApBcHBsZSBJbmMuMRQwEgYDVQQLDAtJ
U08gUmFEIFNSRTETMBEGA1UEAwwKQXBwbGUgSW5jLjCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALqr/uX/uo7PlTFdYNSWKa5lVM99fiUGeMPDV92osljJ
e8V/RDli1loSLKqNEkKUHX3ltRMFQPBLVie1jVoQ2NhC9FEY0UHJuhp9/LVPqYNp
tyS/ySqQaALVoXPUThOfd4jYxIA+OXlVSGrwJ8WHyLXOZWtfuFqgVfPPzBiu+G2T
Vk4D+IR5dM5Ni3sLfhTcbmU40frVYJV/KLN8AhLA7FRGrjYFQ19G6vUXvhEBQI/W
S5P511oRn/w3bgpXYyV8LMeltvSC1x4LKwhhtUVXRRfr4vGHsGDleiqXszgJyZwb
SvD0omhes4VNiq68sZUmbSLj5B2pakFLClaS1WWvlYkCAwEAAaOCAW4wggFqMAkG
A1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMGYG
A1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0cHM6Ly9k
LnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNv
bS9ycGEwHwYDVR0jBBgwFoAUljtT8Hkzl699g+8uK8zKt4YecmYwKwYDVR0fBCQw
IjAgoB6gHIYaaHR0cDovL3N2LnN5bWNiLmNvbS9zdi5jcmwwVwYIKwYBBQUHAQEE
SzBJMB8GCCsGAQUFBzABhhNodHRwOi8vc3Yuc3ltY2QuY29tMCYGCCsGAQUFBzAC
hhpodHRwOi8vc3Yuc3ltY2IuY29tL3N2LmNydDARBglghkgBhvhCAQEEBAMCBBAw
FgYKKwYBBAGCNwIBGwQIMAYBAQABAf8wDQYJKoZIhvcNAQELBQADggEBAHkyo1PB
nvH6yBI0htL2PZmhZVxgAXiiwXyOT4S5HjUzWnJni+GREZFuW/a07uCiz+2Rfgjq
ArdddRpLHk6x/UphEbbYS0UjvLd1qEjCtiGj9hE0kmqoC6DA48LRYY+PJq89mkSt
I4uL7xYbo4UrTxQIaQ6IZvWhY8x6+7B+Y7407hxsJWWXWHHsRqMyHfgewM49k3LY
qS4oEio8OQCJmTrlCPXsnWXbH88r4carKF6pPTI22wHKT/QPnp3ANoBLdXToVrs6
94kr9Q3IJFNdPcOj8DEApHtg97L2K0phzuXxTz/HgrwSTnpSxNpSJAjD+TgH3FRZ
YBqUz3xFYw/Ixqo=
-----END CERTIFICATE-----
EOCERT

    @auth = Gamecenter::Auth.new
  end

  it 'has a version number' do
    expect(Gamecenter::Auth::VERSION).not_to be nil
  end

  # describe "#verify_player" do
  #   it 'returns true if player with Credentials could be verified' do
  #     @verified = @auth.verify_player @player_id, @bundle_id, @public_key_url, @signature, @salt, @timestamp
  #     expect(@verified).to eq(true)
  #   end
  # end

  describe '#verify_public_key_url' do
    it "returns true if public key URL points to Apple's secure servers" do
      @verified = @auth.verify_public_key_url @public_key_url
      expect(@verified).to eq(true)
    end

    it "returns false if public key URL doesn't point do Apple's secure servers" do
      @verified = @auth.verify_public_key_url 'http://www.rubygems.org'
      expect(@verified).to eq(false)
    end
  end

  describe '#get_public_key_certificate' do
    it 'tests the hardcoded cert' do
      expect(@cert).to be_an_instance_of OpenSSL::X509::Certificate
      expect(Time.now <=> @cert.not_after).to eq(-1)
    end
  end

  describe '#verify_public_key_certificate' do
    it 'returns true when hardcoded certificate is valid' do
      @verified = @auth.verify_public_key_certificate @cert
      expect(@verified).to eq(true)
    end
  end

  describe '#verify_signature' do
    it 'returns true when signature is valid' do
      @payload = "#{@player_id}#{@bundle_id}#{[@timestamp.to_i].pack('Q>')}#{Base64.decode64(@salt)}"
      @verified = @auth.verify_signature @cert, Base64.decode64(@signature), @payload
      expect(@verified).to eq(true)
    end

    it 'returns false when signature is invalid' do
      @payload = "G:01234567#{@bundle_id}#{[@timestamp.to_i].pack('Q>')}#{Base64.decode64(@salt)}"
      @verified = @auth.verify_signature @cert, Base64.decode64(@signature), @payload

      expect(@verified).to eq(false)
    end

    it 'returns true when running one successful test after a failed one' do
      # generate payload that doesn't match signature
      @payload = "G:01234567#{@bundle_id}#{[@timestamp.to_i].pack('Q>')}#{Base64.decode64(@salt)}"
      @verified = @auth.verify_signature @cert, Base64.decode64(@signature), @payload
      expect(@verified).to eq(false)

      # generate valid payload
      @payload = "#{@player_id}#{@bundle_id}#{[@timestamp.to_i].pack('Q>')}#{Base64.decode64(@salt)}"
      @verified = @auth.verify_signature @cert, Base64.decode64(@signature), @payload
      expect(@verified).to eq(true)
    end
  end

end
