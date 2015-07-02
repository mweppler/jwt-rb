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
