# rust_simple_jwt
Simple jwt server supporting rsa, hmac and ecdsa

Realized as rest service via login, verify and refreshToken endpoints with json data exchange.
Now it's just a service without stop lists, just generate on a fly.

Endpoints:
  </api/status>
    - Output: 
        json structure like {"result": bool, "message": String} and of course an HTTP status code.
  </api/auth/login/{name}>
    - Input:
        {name} - is one of rsa, hmac or ecdsa
        json structure like {"user_name": String} (Of course you it can be extended)
    - Output:
        json structure like {"access_token": String, "refresh_token": String} and of course an HTTP status code.
  </api/auth/verify/{name}>
    - Input:
        {name} - is one of rsa, hmac or ecdsa
        json structure like {"token": String}
    - Output:
        json structure like {"result": bool, "message": String} and of course an HTTP status code.  
  </api/auth/refreshToken/{name}>
    - Input:
        {name} - is one of rsa, hmac or ecdsa
        json structure like {"token": String} (you can send refresh token here)
    - Output:
        json structure like {"access_token": String, "refresh_token": String} and of course an HTTP status code.  
