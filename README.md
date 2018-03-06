# SSH AUTH API

This simple service provides a mechanism to generate SSH RSA key pairs, store the public key, and return an authorized_keys file that can be used by sshd.  This could be used to effecitvely replace a private myproxy/gsi-ssh configuration.

## Quick Example

Here is a quick example of the service endpoints using curl.

    # Create a Key Pair
    curl  -X POST -H "Authorization: Basic auser:pass" http://localhost:5000/create_pair > ~/.ssh/mykey
    # Retrieve keys and append to an authorized_keys file
    curl http://localhost:5000/get_keys >> ~/.ssh/authorized_keys

    # Use the keys with ssh
    ssh -i ~/.ssh/mykey auser@localhost

Note: An unencrypted end-point should not be used in production.  In a real-world use case, the get_keys call would be made by sshd through a Configuration parameter.  So the user would only call the create_pair endpoint.


## REST API

### /create_pair

Method: POST
Header: Basic Username:password
Data: None

This end-point authenticates the user using the provided username and password and, if successful, generates a SSH key pair.  The private key is returned in the response and not stored.  The pubic key is saved in a database and is associated with the user.  Authentication is determined by the PAM configuration associated with the service (sshauth).

### /get_keys/<username>

Method: GET
Parameter: username
Header: None

This end-point returns the list of public keys for the user.  This would typically be called by sshd through a configuration option (see below).


### /reset

Method: DELETE

Not yet implemented.

## Configuration

### PAM Configuration

Authentications is configured via PAM.  Currently just the authenticate interface is used.  Here is an example configuration that uses the common auth stack on the system.

    #/etc/pam.d/ssh_auth
    @include common-auth


### SSHD Configuration

To integrate with SSHD, first create a wrapper that uses curl to call get_keys.

    echo "#!/bin/sh" > /usr/sbin/ssh-keys-api
    echo "curl https://authapi.me.com/get_keys/${1}" >> /usr/sbin/ssh-keys-api
    chmod 755 /usr/sbin/ssh-keys-api

Then used the `AuthorizedKeysCommand` configuration option for sshd to have sshd use the script to retrieve the public keys for the user.  Here is an example of the relevant configuration options for sshd_config.

    AuthorizedKeysCommand /usr/lib/nersc-ssh-keys/NERSC-keys-api
    AuthorizedKeysCommandUser nobody
    AuthorizedKeysFile /dev/null



## Future Improvements

### Scopes and Expiration

One design goal is to have the service limit the scope of keys and expire request.  The service already has stubs for storing a scope and expiration time for the key.  This could be used to restrict how long keys could be used before the user would need to re-authenticate to generate a new key pair.  The scope can be used to restrict keys to a specific node or purpose.  

In addition, the generation of keys tied to a scope would likely be restricted either to some set of calling nodes or via some service token.
