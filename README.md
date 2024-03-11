
Configuration
-------------

When running ddsend, you must specify a config file location. There is no
default configuration. Luckily, the only required setting is `socket path`,
since the `admin socket path` option can be set using `DDSEND_ADMIN`.

After the first load, you can send a `POST` request to `/load` on the admin
socket to force the daemon to reload the config file from a specified path (or
the previously configured location if no path is given).

Error Handling
--------------

The daemon has two phases of running: Configuration and Work.

During the configuration phase we read config files, open sockets, and all
that, and generally error out at the first sign of something not working. Once
everything is all set, we switch to the work phase.

During the work phase, we listen to incoming connections and try to handle
every single error, avoiding any sort of panic or downtime whenever possible.
During this state, we will read from a socket giving user commands, but no such
command should take the system down, unless its an explicit shutdown request.

Even an update of the settings should only apply to not-yet-in-progress
connections, so in general it should be unnoticable to the outside world.

Threat Model
------------

Resources are identified by their IDs, and all requests wanting to access some
resource with a given ID needs to authorize their requests by providing a
cryptographically signed ID as an `Authorization: Bearer` token as part of all
requests to some ID.

To do so, the upload endpoint will return both an ID to the data as well as a
nonce which must be used to generate a key to sign and decrypt the data.

Specifically, the uploading process is as follows:
- The user generates a nonce and using HKDF SHA-256 generates 3 keys:
        1. A metadata encryption key  (128 bit AES-GCM)
        2. An encryption key for the data you want to send (128 bit AES-GCM)
        3. A signing key for authenticating requests (HMAC-SHA 256)

How Does This Work
------------------

A file is uploaded by hitting the `/api` endpoint with a `POST` request with
the body containing the data you wish to upload. On success, the server will
respond with `201` with `Content-Location` being set to the data's secret ID
and `Authorization` being set to an encryption key used to sign the secret ID
to authenticate further requests and decrypt the data. The request must contain
headers `X-Max-Downloads` and `X-Seconds-Until-Expiry` which set the number of
downloads and number of seconds respectively which afterward the uploaded data
will no longer be availible to access using the given ID.

To retrieve the metadata for a file given the secret ID, hit the
`/api/metadata` endpoint with a `GET` request.

To download a file given the secret ID, hit the `/api` endpoint with a `GET`
request.
