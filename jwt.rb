#!/usr/bin/env ruby

require 'base64'
require 'json'
require 'openssl'

class Jwt
  attr_reader :b64_hash, :b64_headers, :b64_payload, :headers, :jwt, :payload, :secret

  def initialize(options = {})
    unless options.empty?
      @headers = options['headers']
      @payload = options['payload']
      @secret = options['secret']
    end
  end

  def key_value_pair_to_hash(kvp)
    Hash[kvp.split(':').map{ |val| val.strip }.each_slice(2).to_a]
  end

  def set_headers
    puts 'Add headers as `key:value`, one per line.'
    puts 'Use `.:.` when finished.'
    headers = {}
    loop do
      key_value_pair = STDIN.gets.chomp
      case key_value_pair
      when '.:.'
        break
      else
        headers.merge!(key_value_pair_to_hash(key_value_pair))
      end
    end
    if headers.empty?
      @headers = { 'alg' => 'HS256', 'typ' => 'JWT' }.to_json
    else
      @headers = headers.to_json
    end
  end

  def set_payload
    puts 'Add payload as `key:value`, one per line.'
    puts 'Use `.:.` when finished.'
    payload = {}
    loop do
      key_value_pair = STDIN.gets.chomp
      case key_value_pair
      when '.:.'
        break
      else
        payload.merge!(key_value_pair_to_hash(key_value_pair))
      end
    end
    if payload.empty?
      @payload = {
        'sub'   => '1234567890',
        'name'  => 'John Doe',
        'admin' => 'true'
      }.to_json
    else
      @payload = payload.to_json
    end
  end

  def set_secret
    print "Enter a `secret`: "
    @secret = STDIN.gets.chomp
    @secret = 'secret' if @secret.empty?
  end

  def encoded_headers
    @b64_headers ||= Base64.urlsafe_encode64 @headers
  end

  def encoded_payload
    @b64_payload ||= Base64.urlsafe_encode64 @payload
  end

  def encrypt
    msg = "#{encoded_headers}.#{encoded_payload}"
    hash = OpenSSL::HMAC.digest('sha256', @secret, msg)
    @b64_hash = Base64.urlsafe_encode64 hash
    @jwt = "#{encoded_headers}.#{encoded_payload}.#{@b64_hash}"
  end

  def decrypt(jwt = '', secret = '')
    if jwt.empty? || secret.empty?
      puts "JWT: '#{jwt}' is empty, or no SECRET: #{secret}"
      exit 1
    end
    @b64_headers, @b64_payload, @b64_hash = jwt.split('.')
    @headers = Base64.urlsafe_decode64 @b64_headers
    @payload = Base64.urlsafe_decode64 @b64_payload
    @secret = secret
    if validate_jwt(jwt, @b64_hash)
      puts 'SIGNATURE VERIFIED'
      puts <<-DECODED
Decoded:
---
#{JSON.pretty_generate(JSON.parse(@headers))}
---
#{JSON.pretty_generate(JSON.parse(@payload))}
---
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  "#{@secret}"
)
---
DECODED
    else
      puts 'INVALID SIGNATURE'
    end
  end

  def validate_jwt(jwt = '', hash = '')
    if jwt.empty? || hash.empty?
      puts "JWT: #{jwt} is empty, or doesn't contain a HASH: #{hash}."
      exit 1
    end
    encrypt
    return jwt == @jwt && hash == @b64_hash
  end
end

if __FILE__ == $0
  puts <<DEMO
DEMO MODE

Creating a JSON Web Token with the following:
---
HEADERS:
#{JSON.pretty_generate(JSON.parse('{"alg":"HS256","typ":"JWT"}'))}
---
PAYLOAD:
#{JSON.pretty_generate(JSON.parse('{"sub":"1234567890","name":"John Doe","admin":"true"}'))}
---
SECRET: "secret"
---

DEMO

  jwt = Jwt.new 'headers' => '{"alg":"HS256","typ":"JWT"}', 'payload' => '{"sub":"1234567890","name":"John Doe","admin":"true"}', 'secret' => 'secret'
  jwt.encrypt
  puts <<DEMO

Paste the token into the 'ENCODED' field on http://jwt.io/
JSON Web Token: #{jwt.jwt}


---


DEMO

  puts <<DEMO
Decrypting a JSON Web Token with the following:
---
JSON Web Token:
---
SECRET: "secret"
---
DEMO
  jwt = Jwt.new
  jwt.decrypt 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOiJ0cnVlIn0=.m15sbUnjbyFU8w7ZOX60aYgCZKqoX8Z0fc-EWbSrlZs=', 'secret'

  puts <<DEMO


---


Or to use interactively in irb or pry

Create and encrypt JSON Web Token:

```ruby
require_relative 'jwt'

jwt = JWT.new
jwt.set_headers
jwt.set_payload
jwt.set_secret
jwt.encrypt
puts jwt.jwt
```

Decrypt and Validate JSON Web Token:

```ruby
require_relative 'jwt'

jwt = Jwt.new
jwt.decrypt '<json-web-token>', '<your-secret>'
```
DEMO
  exit 0
end
