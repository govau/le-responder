# le-responder

This bosh release contains a web server that has a management interface for certificates.

## How does it work?

There are a number of moving parts:

1. `le-responder` application. This is included in this release. It provides a UI for managing certificates, and responds to ACME HTTP challenges.
2. A `credhub` instance is used to provide storage for `le-responder`.
3. The `credhub` instance needs a database.
4. `le-responder` needs a `uaa` to integrate with for administrators who need to login.
5. `credhub` also needs a `uaa` to integrate with, so that `le-responder` can authenticate to it.

Typically both `le-responder` and `credhub` are deployed on a singleton instance as part of a CloudFoundry deployment.

The [add-le-responder-to-cf.yml](./example/add-le-responder-to-cf.yml) operator file creates such an instance, and also sets up the appropriate linkages with the `cf` `uaa`, and creates a database for use with the dedicated `credhub` installation.

You will also probably want to set an external IP address for this instance, such as with:

```yaml
- type: replace
  path: /instance_groups/name=tls-credhub/networks
  value:
  - name: Public
    default: [dns, gateway, addressable]
  - name: Internet
    static_ips: [((leresponder_external_ip))]
```

If you want to use an external database (such as RDS), the following might be useful:

```yaml
- type: remove
  path: /variables/name=tlscredhub_database_password

- type: replace
  path: /instance_groups/name=tls-credhub/jobs/name=credhub/properties/credhub/data_storage/type
  value: ((external_database_type))
- type: replace
  path: /instance_groups/name=tls-credhub/jobs/name=credhub/properties/credhub/data_storage/username
  value: ((external_tlscredhub_database_username))
- type: replace
  path: /instance_groups/name=tls-credhub/jobs/name=credhub/properties/credhub/data_storage/password
  value: ((external_tlscredhub_database_password))
- type: replace
  path: /instance_groups/name=tls-credhub/jobs/name=credhub/properties/credhub/data_storage/host
  value: ((external_tlscredhub_database_address))
- type: replace
  path: /instance_groups/name=tls-credhub/jobs/name=credhub/properties/credhub/data_storage/port
  value: ((external_database_port))
- type: replace
  path: /instance_groups/name=tls-credhub/jobs/name=credhub/properties/credhub/data_storage/database
  value: ((external_tlscredhub_database_name))
```

Finally, you might want to set the allowed users in an operator file like this:

```yaml
- type: replace
  path: /instance_groups/name=tls-credhub/jobs/name=le-responder/properties/config/servers/admin_ui/allowed_users?
  value:
  - user1@example.com
  - user2@example.com
```

## What does it do?

The properties section of the example manifest gives the best idea, but roughly speaking, once a day it will check for any certificates that are within `days_before` days of expiration and will attempt to refresh them using an ACME HTTP challenge.

Anytime a new certificate is issued, a new tarball of certificates and keys will be generated, and then if no more are generated in the next 30 seconds, that tarball will be uploaded to the S3 object specified in the config.

It is then expected that another process, such as a Concourse pipeline, will take care of applying to running frontend servers.

## Example pipeline

We use the following pipeline: <https://github.com/govau/cga-frontend-config>

It is responsible for firing when changes take place to either the certificate tarball, or another repository where we store HAProxy config.

If either causes a change, it builds a new tarball with combined HAProxy config and certificates and then calls a process on the frontend routers to initiate an update.

## Router changes

The above pipeline expects HAProxy to be colocated on the `gorouter` instances. We use the following operator file to do so:

```yaml
# Ops for adding our frontend proxy server from this BOSH release:
# https://github.com/govau/frontend-boshrelease
- type: replace
  path: /releases/-
  value:
    name: frontend
    version: 0.16.0
    sha1: cf337ea2e6af36acc4bd3c17002485d06ad2ac73
    url: https://github.com/govau/frontend-boshrelease/releases/download/v0.16.0/frontend-0.16.0.tgz

# This HAProxy job sits on the same instances as the CF routers
- type: replace
  path: /instance_groups/name=router/jobs/-
  value:
    name: haproxy
    release: frontend
    properties:
      config_bucket: "((frontend_config_bucket))"
      default_config_object: release.tgz
      fallback_config: |
        frontend http
            mode http
            bind *:1080
            acl acme_challenge path_beg -i /.well-known/acme-challenge/
            http-request redirect location http://"${FE_ACME_ADDRESS}"%[capture.req.uri] code 302 if acme_challenge
            http-request redirect scheme https code 301 unless acme_challenge
            log global
            option httplog
            option http-buffer-request
            timeout client 5s
            timeout http-request 10s
      env:
        FE_ACME_ADDRESS: "((leresponder_external_hostname))"
        FE_DOPPLER_HOST: "doppler.((system_domain)):4443"
      # AWS load balancers currently don't support HTTP healthchecks on a TCP target group,
      # so we signal a drain by shutting down the healthcheck port completely.
      drain_command: "disable frontend healthcheck"
      drain_seconds: 120
      syslog_address: 127.0.0.1:1543
      syslog_format: rfc5424

- type: replace
  path: /instance_groups/name=router/jobs/name=gorouter/properties?/router/drain_wait
  value: 120

# Collocate syslog_to_loggregator. HAProxy sends its logs to this syslog, and
# they then get forwarded to loggregator

- type: replace
  path: /releases/-
  value:
    name: syslog_to_loggregator
    url: https://github.com/govau/syslog-to-loggregator-boshrelease/releases/download/v0.5.0/syslog_to_loggregator-0.5.0.tgz
    version: 0.5.0
    sha1: f1e28187d971c31084f72013f2c197d19b46bafc

- type: replace
  path: /instance_groups/name=router/jobs/-
  value:
    name: syslog_to_loggregator
    release: syslog_to_loggregator
    properties:
      syslog_to_loggregator:
        source_name: haproxy
        syslog_port: 1543
```

## TODO

- Consider not using `credhub` and instead use simpler abstraction (such as S3) for state
