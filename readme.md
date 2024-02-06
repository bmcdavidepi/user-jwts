# User Jwts 

Usage

```ps
docker compose build --pull api api-tests
docker compose run --rm api-tests
```

To inspect test container

```ps
docker compose run --rm -i --entrypoint /bin/bash api-tests
```

Docker Run Issue

The test ShouldResolveSecretWithToken fails with when it works on local machine.

```txt
Microsoft.IdentityModel.Tokens.SecurityTokenSignatureKeyNotFoundException: IDX10500: Signature validation failed. No security keys were provided to validate the signature.
```