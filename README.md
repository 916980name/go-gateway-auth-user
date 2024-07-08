### Config file
```yaml
serverOptions: 
  Addr: 127.0.0.1 # server listen address
    #Runmode: debug
  Port: 8989 # server listen port
log:
  level: INFO
  format: json
  output-paths: 
    - stdout
    - /tmp/go-api-gateway.log
db:
  redis: # for cache
    connectionString: redis://localhost:6379
caches:
  - name: cache-1 # name should unique in 'caches'
    type: redis # redis as cache
    max: 300 # max allowed key size 
    defaulExpireMinute: 1440 # default expire time
  - name: cache-1-blacklist
    type: mem # server memory as cache
    max: 10
    defaulExpireMinute: 10
rateLimiters:
  - name: rl-1 # name should unique in 'rateLimiters'
    cacheName: cache-1 # using which 'caches'
    max: 3 # trigger limit shreshold
    refillInterval: 30 # in seconds
    refillNumber: 1 # refill token number
  - name: rl-1-blacklist
    cacheName: cache-1-blacklist
    max: 3
    refillInterval: 300
    refillNumber: 1
sites:
  - hostname: www.host1.com # domain name
    #    onlineCache: cache-1-online # If this active, login user will stored in cache. server hold the login state
    inOutFilter: # login sign JWT access token, refresh token, could response in header or cookie
      limiterName: rl-1-blacklist # login or logout hanler must protected by ratelimiter
      loginPath: # for multiple login ways. Any paths list here must be defined in 'sites.routes'
        - /login
        - /signin
      logoutPath: /logout # Any paths list here must be defined in 'sites.routes'
      refreshTokenPath: /refreshToken # Any paths list here must be defined in 'sites.routes'
      cookieEnabled: true # If this active, access token will set in response cookie
    routes: # proxy routes
      - path: /refreshToken
        method: GET # If not set, for all methods
        rateLimiter: # could specify ratelimiter for a 'route'
          limiterName: rl-1
          limitType: limiterIP, limiterUser # limit by IP or by User or both. Must have access token in request if limit by User
        # refreshToken path do not need 'route'
      - path: /logout
        method: GET, POST
        route: 127.0.0.1:8080 # proxy destination
        privilege: 10010001 # user privilege must in the access token
      - path: /login
        method: POST
        route: 127.0.0.1:8080
        rateLimiter: 
          limiterName: rl-1
          limitType: limiterIP
      - path: /signin
        route: 127.0.0.1:8080
        rateLimiter: 
          limiterName: rl-1
          limitType: limiterIP
    jwtConfig: # for JWT token, only support RSA256, need private & public key.
      rsaPrivateKey: |
        -----BEGIN PRIVATE KEY-----
        MIIEvAIB...
        ...
        ...VbJ4A==
        -----END PRIVATE KEY-----
      rsaPublicKey: |
        -----BEGIN PUBLIC KEY-----
        MIIBIjANB...
        ...
        ...QAB
        -----END PUBLIC KEY-----
  - hostname: other-service.host1.com # multiple host support
    rateLimiter: # ratelimiter alse could for all
      limiterName: rl-2
      limitType: limiterIP, limiterUSER
    inOutFilter:
      limiterName: rl-2-blacklist
      loginPath: 
        - /auth
      logoutPath: /logout
      refreshTokenPath: /refreshToken
    routes:
      - path: /refreshToken
        method: GET
      - path: /logout
        method: GET, POST
        route: 127.0.0.1:8080 
        privilege: p1 
      - path: /auth
        method: POST
        route: localhost:8081
    jwtConfig:
      rsaPrivateKey: |
        -----BEGIN PRIVATE KEY-----
        ...
        -----END PRIVATE KEY-----
      rsaPublicKey: |
        -----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----
```