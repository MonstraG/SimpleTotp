# SimpleTotp

This is a Golang library for generating time-based one-time passwords (TOTP) as defined in 
[RFC6238](https://datatracker.ietf.org/doc/html/rfc6238).

There are few key things to note:

1. Parameters, such as `digit count`, `t0`, `time step` and the hashing operation are not configurable.
2. As opposed to other implementations you might want to actually use, like
[otp, the first in google](https://github.com/pquerna/otp), this doesn't expose `HOTP` functions because, 
in my humble opinion, no one probably actually needs it.
3. As opposed to other implementations, there is no way to easily validate the codes, I didn't write that yet)