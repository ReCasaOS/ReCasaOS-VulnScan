# ReCasaOS-VulnScan

An optional module of [ReCasaOS](https://github.com/ReCasaOS): it scans the images of the
box's containers for known vulnerabilities with [Trivy](https://github.com/aquasecurity/trivy),
every night at 05:30, once right after it is installed, when an app is installed or updated, and on demand.

It keeps the critical and high vulnerabilities that have a fix. The dashboard puts a badge on
an app, and the box sends an alert, in one case only: a critical vulnerability in an app for
which an update is offered. That is when there is something to do.

## What it needs

- About 2.5 GB beside Docker's data: Trivy's vulnerability database is 1.7 GB, and the first
  scan of an image copies the whole image there for the time of the scan.
- The network once a day, for the database (mirror.gcr.io, then ghcr.io). A scan itself asks
  nothing of the network and sends nothing: the names of your images never leave the box.

Images that hold Java libraries are scanned for their system packages only (the Java
database is another 1.5 GB); the app's window says so.

## The routes

Under `/v2/vuln_scan`, for the administrator only: `GET /status`, `GET /apps`,
`GET /apps/{app}`, `POST /scan`. See `api/vuln_scan/openapi.yaml`.

One event on the message bus, source `vuln-scan`: `vuln:found`, with `apps` and `count`.

## The Trivy that is shipped

The release archives carry Trivy as `/usr/bin/casaos-trivy`. `trivy.lock` pins its version
and the SHA-256 of the release for each architecture; `scripts/fetch-trivy.sh` refuses
anything else. To move to a newer Trivy, change `trivy.lock` in a pull request, with the sums
of the release's own `checksums.txt`, and not before the release is three days old.

## Tests

    go generate ./...
    go test ./...
    sh scripts/test-fetch-trivy.sh
