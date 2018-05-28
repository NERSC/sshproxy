# SSH AUTH API

This simple service provides a mechanism to generate SSH RSA key pairs, store the public key, and return an authorized_keys file that can be used by sshd.  This could be used to effectively replace a private myproxy/gsi-ssh configuration.

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

### /create_pair/<scope>

Method: POST  
Header: Basic Username:password  
Data: JSON encoded dictionary that may contain an 'skey' for the scope.

Create a key pair for the specified scope.  The scope may require a share key
(skey) which must be provided in the data block which is a JSON encoded dictionary.
The scope may use an ssh CA certificate.  If the scope does use a CA certificate,
the return will be the private key followed by the signature string.  These
returns need to be split into private key (e.g. id_rsa) and the certificate
file (e.g. id_rsa-cert.pub) in order for ssh to be make use of them.


### /get_keys/\<username\>

Method: GET  
Parameter: username  
Header: None  

This end-point returns the list of public keys for the user.  This would typically be called by sshd through a configuration option (see below).


### /reset

Method: DELETE  

Not yet implemented.

## Configuration

### Scopes

Scopes allowing defining and limiting how a key can be created and used.  scopes
are defined in the config.yaml.  Each scope has a name space and can list
multiple optional enforcements.  Some constraints apply to the creator (e.g. the host that issues the create_pair).  Others constraints apply to the remote host (e.g. the host that the SSH connection will originate from).

Here is an example config file.

```yaml
scopes:
  scope1:
     skey: scope1-secret
     cacert: ./cacert
     lifetime: 1d
  scope2:
     allowed_create_addrs:
       - '127.0.0.1'
```

**skey**: A shared key that must presented by the creator.  The shared key must be provided in the data block of the POST create_pair operation.

**allowed_create_addrs**: The list of IP addresses that create_pair requests can originate from.

**allowed_remote_addrs**: The list of IP addresses that the ssh connection can
originate from.  This requires a CA certificate for the scope.

**allowed_users**: The list of users who are allowed to use the scope.

**lifetime**: The lifetime of the key.  If it is an integer it is treated as
minutes. If it ends in "d", "w", "y", then it is treated as day, weeks or years
respectively.

**cacert**: Specify a ssh CA certificate to user for signing the public key.

### PAM Configuration

Authentications is configured via PAM.  Currently just the authenticate interface is used.  Here is an example configuration that uses the common auth stack on the system.

    #/etc/pam.d/ssh_auth
    @include common-auth


### SSHD Configuration

There are two methods for configuring the ssh daemon: AuthorizedKeysCommand or
TrustedUserKeys.  The first issues a get_keys request for each ssh connection
to get the list of active keys for a user.  The second uses the CA certificate
mechanism provided by ssh.

#### AuthorizedKeysCommand configuration

To integrate with SSHD, first create a wrapper that uses curl to call get_keys.

    echo "#!/bin/sh" > /usr/sbin/ssh-keys-api
    echo "curl https://authapi.me.com/get_keys/${1}" >> /usr/sbin/ssh-keys-api
    chmod 755 /usr/sbin/ssh-keys-api

Then used the `AuthorizedKeysCommand` configuration option for sshd to have sshd use the script to retrieve the public keys for the user.  Here is an example of the relevant configuration options for sshd_config.

    AuthorizedKeysCommand /usr/lib/nersc-ssh-keys/NERSC-keys-api
    AuthorizedKeysCommandUser nobody
    AuthorizedKeysFile /dev/null
