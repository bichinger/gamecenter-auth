require 'spec_helper'

describe Gamecenter::Auth do
  before :each do
    @player_id = 'G:123148854'
    @bundle_id = 'de.bichinger.test.gamekit-auth'
    @signature = 'SGKgszgKffUshV4aMe0aQHAvzSointPjBlfF2MK34gHY50DycZlC5gwKDpRb+gBCS2OHQNLSRctYV5WORYsDbjAcNdrzR2Tl0oDMptpBiVJQX+kCilv45Fbs7szEJ2jw/4Xl/CAFlX/HtRxYZKb4oeC/knB5ueuDGcAyjFZJkl8FmFvyRn2ZeO0pGfefzQ2lz3bgHkwgcY+w8ZMQ5wIoHkgt4x44H21hnI5he/G0q48Il0lc3frWiojeZn2UWIo8j601svFHSDkX3mx9SJrYeP4f8goJ8ax1/fVVHxSdh2+uKW+9Zz/gAbrAC4xtVUiz12DjHZf9G6hxZ0etrjZYBQ=='
    @salt = 'Yt1c3Q=='
    @timestamp = 1445940012818
    @public_key_url = 'https://static.gc.apple.com/public-key/gc-prod-6.cer'

    # this is a downloaded (from public key url) public key certificate
    # converted to base64:
    # openssl x509 -inform der -in gc-prod-6.cer -out outfile.cer
    @cert = OpenSSL::X509::Certificate.new <<~EOCERT
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
    it 'test the hardcoded cert' do
      expect(@cert).to be_an_instance_of OpenSSL::X509::Certificate
      expect(@cert.not_after > Time.now).to eq(true)
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
