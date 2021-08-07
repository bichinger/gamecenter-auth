# gamecenter-auth

Ruby gem for iOS GameKit/Game Center player authentication using the "Identity Verification Signature" provided by the generateIdentityVerificationSignatureWithCompletionHandler method in Apple's GameKit framework 

This gem fully replaces the gamekit-auth-ruby gem previously available at https://rubygems.org/gems/gamekit-auth-ruby and https://github.com/bichinger/gamekit-auth-ruby.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'gamecenter-auth'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install gamecenter-auth

## Usage

Gamecenter::Auth takes all parameters your iOS-App receives from the call generateIdentityVerificationSignatureWithCompletionHandler.

See https://developer.apple.com/library/prerelease/ios/documentation/GameKit/Reference/GKLocalPlayer_Ref/index.html

### Configuration

!This is likely to be changed a little in future versions!

Gamecenter::Auth can be statically configured using the following parameters (values show the default values):

```ruby
# if for some reason you don't want the public key certificate verified
# against the issuer's (Apple) certificate, set this to false
Gamecenter::Auth.verify_issuer_certificate = true

# public keys won't change often, this saves a lot of HTTP requests
Gamecenter::Auth.cache_public_keys = true
# cache this many public keys (has to be 1 at least!)
Gamecenter::Auth.public_key_cache_entries = 10

# if the salt is already base64-decoded, set this to false 
Gamecenter::Auth.base64_decode_salt = true
# if the signature is already base64-decoded, set this to false 
Gamecenter::Auth.base64_decode_signature = true

# HTTP timeouts in seconds
Gamecenter::Auth.request_public_key_open_timeout = 5
Gamecenter::Auth.request_public_key_read_timeout = 5
Gamecenter::Auth.request_public_key_ssl_timeout = 5

```

### Example usage

```ruby
player_id = 'G:123148854'
bundle_id = 'de.bichinger.test.gamekit-auth'
public_key_url = 'https://static.gc.apple.com/public-key/gc-prod-2.cer'
signature = 'SGKgszgKffUshV4aMe0aQHAvzSointPjBlfF2MK34gHY50DycZlC5gwKDpRb+gBCS2OHQNLSRctYV5WORYsDbjAcNdrzR2Tl0oDMptpBiVJQX+kCilv45Fbs7szEJ2jw/4Xl/CAFlX/HtRxYZKb4oeC/knB5ueuDGcAyjFZJkl8FmFvyRn2ZeO0pGfefzQ2lz3bgHkwgcY+w8ZMQ5wIoHkgt4x44H21hnI5he/G0q48Il0lc3frWiojeZn2UWIo8j601svFHSDkX3mx9SJrYeP4f8goJ8ax1/fVVHxSdh2+uKW+9Zz/gAbrAC4xtVUiz12DjHZf9G6hxZ0etrjZYBQ=='
salt = 'Yt1c3Q=='
timestamp = 1445940012818

auth = Gamecenter::Auth.new
success = auth.verify_player(player_id, bundle_id, public_key_url, signature, salt, timestamp)

puts success ? 'player verified' : 'player not verified'
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are very welcome on GitHub at https://github.com/bichinger/gamecenter-auth.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

