..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

OCI registries
==============

shirudo delivers packages and upatch trees through OCI registries, the
servers that also hold container images. This page explains what a
registry stores and how a client talks to it, and then which parts of
what ``shirudo bpm`` fetches are signed and which are only
content-addressed.

Why a registry
--------------

A target has to fetch signed artifacts from somewhere. A dedicated
update server would be one more service to build, authenticate and keep
available, and a plain web server has no notion of versions or of
immutable content. Most organizations already run an OCI registry, or
rent one, with access control, replication and mirrors in place.

We do not trust the registry. Whoever controls it, or the network path
to it, can change what it serves. Everything that decides what a target
loads is therefore either signed with the operator's key or named by a
digest inside something signed.

Repositories, blobs and tags
----------------------------

A registry is a server that implements the OCI Distribution
Specification. It holds repositories, each a named collection of
content such as ``team/kernel-fixes``. A repository contains blobs,
which are opaque byte strings, and manifests, JSON documents that
describe blobs.

A tag is a name of up to 128 characters, such as ``1.4.0`` or
``stable``, that points at one manifest in a repository. Tags are
mutable: anyone allowed to push to the repository can move a tag to
another manifest at any time.

Every blob and manifest is also addressed by its digest, the hash of
its exact bytes, written ``sha256:<hex>``. A client hashes what it
receives and compares.

A digest proves only that the bytes match the name. When a client
resolves a tag, the registry picks the manifest, and with it the
digests the client then checks. Content addressing protects integrity
only from the point where a digest comes from a source the client
already trusts.

Manifests, configs and layers
-----------------------------

An image manifest, media type
``application/vnd.oci.image.manifest.v1+json``, names a ``config`` blob
and a list of ``layers``. Each entry is a descriptor: a ``mediaType``
that says what the blob is, its ``digest`` and ``size``, and optional
``annotations`` such as ``org.opencontainers.image.title``. In a
container image the config holds runtime settings and the layers are
file system archives. Because the manifest names each blob by digest,
the manifest's own digest pins everything it references.

An image index, ``application/vnd.oci.image.index.v1+json``, is a
manifest of manifests, used mostly to publish one image for several
platforms under one tag. ``shirudo bpm`` reads image manifests only.

Version 1.1 of the image specification describes how to store content
other than container images. ``artifactType`` names the kind of
artifact. When there is no configuration to store, the ``config``
descriptor points at the two-byte blob ``{}`` with media type
``application/vnd.oci.empty.v1+json``, and ``artifactType`` is then
required. A manifest can also name another manifest as its
``subject``; registries list such referrers, for example a signature,
through the referrers API.

Talking to a registry
---------------------

The Distribution Specification is an HTTP API under ``/v2/``. A client
pulls a manifest with ``GET /v2/<name>/manifests/<reference>``, where
the reference is a tag or a digest. It pulls a blob with
``GET /v2/<name>/blobs/<digest>``, which registries often redirect to
object storage. To push a blob, it opens an upload with
``POST /v2/<name>/blobs/uploads/`` and sends the bytes with a ``PUT``
to the returned ``Location``, adding ``?digest=<digest>``. The registry
refuses bytes that do not match. A ``PUT`` to
``/v2/<name>/manifests/<tag>`` pushes a manifest and moves the tag.

Authentication is outside the OCI specifications. Most registries
implement the bearer token flow of the Distribution project. A request
without credentials gets ``401`` with a challenge such as
``WWW-Authenticate: Bearer realm="...",service="...",scope="..."``. The
client asks the realm for a token, presenting a user name and password
if it has them, and repeats the request with
``Authorization: Bearer <token>``. Some registries accept HTTP Basic
authentication instead. Container tools keep one base64
``user:password`` per registry host in the ``auths`` object of a
``config.json``.

Shirudo follows blob redirects to storage hosts. Only the configured
registry's scheme, host and port may return a challenge that starts
authentication. The registry may name a separate token service.

How shirudo uses a registry
---------------------------

The operator publishes with ``shirudo bpm push`` and
``shirudo bpm tree append``, which run in the ``shirudo-build`` helper.
A target fetches with ``shirudo bpm repo update``, ``install``,
``upgrade``, ``pull`` and ``tree sync``. Every object is an image
manifest with shirudo's own media types:

.. list-table::
   :header-rows: 1
   :widths: 20 30 50

   * - Object
     - Location
     - Content
   * - Package
     - ``<repository>:<version>``
     - One ``application/vnd.shirudo.bpm.package.v1+gzip`` layer, the
       ``.bee`` archive, and a config of media type
       ``application/vnd.shirudo.bpm.config.v1+json``.
   * - Package certificate
     - Referrer of the package manifest
     - The signing certificate as ``application/pkix-cert``. No
       ``shirudo bpm`` command reads it.
   * - Repository index
     - ``<namespace>/bpm-index:stable``, one per repository namespace
     - ``application/vnd.shirudo.bpm.index.v1+json`` and its detached
       CMS signature,
       ``application/vnd.shirudo.bpm.index.signature.v1``.
   * - Tree publication
     - ``<repository>:<reference>``, ``stable`` by default
     - ``application/vnd.shirudo.upatch.tree.v1+json`` and its detached
       CMS signature,
       ``application/vnd.shirudo.upatch.tree.signature.v1``.
   * - Tree artifact
     - ``<repository>:upatch-<id>-<hex>``
     - One ``application/vnd.shirudo.upatch.v1`` layer, a signed
       ``.upatch``. ``<hex>`` is the start of its payload SHA-256.

The index, the tree publication and the tree artifacts use the empty
config and set ``artifactType``.

``bpm push`` uploads the blobs, the package manifest by digest and the
certificate referrer, then, given signing material, a new signed index,
and moves the version tag last. The index lists every package version
pushed to that registry host with signing material, each with its
repository, manifest digest, package digest and size. ``bpm push``
refuses to list a version again with different digests.

On a target, the repository definitions and their certificates come
from the signed config image. ``bpm repo update`` fetches each
repository's index, checks both layers against their digests, verifies
the signature and caches the index. ``bpm install <source>/<name>``
then fetches the package manifest by the digest the index names, checks
the package layer against the index and loads the upatches inside
through the signed load path. ``bpm tree sync`` verifies the
publication and fetches each artifact by the manifest and layer digests
the publication names.

The client follows redirects for blob requests only and never sends
the ``Authorization`` header to another host. It reads no response
larger than 16 MiB into memory and writes no package larger than 256 MiB
to disk. Each transfer ends after a minute plus the time the most it may
carry takes at 128 KiB a second, so that a registry that answers a few
bytes at a time cannot hold a command, and the config operation lock it
holds, any longer. Credentials come from ``BPM_OCI_USERNAME`` and
``BPM_OCI_PASSWORD``, or from the registry's ``auth`` entry in
``REGISTRY_AUTH_FILE``, ``$DOCKER_CONFIG/config.json`` or
``$HOME/.docker/config.json``, and ``BPM_OCI_BEARER_TOKEN`` supplies a
token directly. Credential helpers are not supported.

What is signed and what is only addressed
-----------------------------------------

Three kinds of objects carry a signature a target checks:

- The ``.upatch`` files inside packages and tree artifacts are signed
  loaders and unload directives. The kernel verifies their ML-DSA-87
  signature at ``BPF_PROG_LOAD`` against the ``.bpf`` keyring.
- A repository index is verified against the certificate its
  repository definition names in the signed config.
- A tree publication is verified against the active config's trusted
  set: the runtime image's primary certificate and the certificates the
  config vouches for, less those it revokes, the primary included. Every
  member must also be in the ``.bpf`` keyring.

Everything else is content-addressed only: manifests, configs, package
archives and artifact blobs. They are trusted because a signed document
names their digests, and Figure 1 shows which document names which
object. A package installed from the index is therefore the one the
operator pushed, but the registry decides whether to serve it at all:
a target reaches each signed document through a tag, which the registry
resolves.

.. figure:: /images/background-oci-digests.svg
   :alt: Two chains of registry objects. For a package, the tag
         bpm-index:stable resolves to the index manifest, which names
         the signed index and its signature; each index entry names a
         package manifest by manifest_digest, and the .bee layer is
         checked against the index's package_digest; the .upatch files
         inside are signed. A direct install by tag reaches the package
         manifest without the index. For a tree, the stable tag resolves
         to the publication manifest, which names the signed publication;
         each operation names an artifact manifest and its .upatch layer
         by digest, and the publication names earlier publications. Both
         chains end at the kernel's signature check against the .bpf
         keyring.

   Figure 1. Which object names which by digest. Solid arrows are
   digests a target checks, dashed arrows are tags the registry resolves.

Limits
------

A signature shows who wrote a document, not that it is current. A
validly signed older index replaces the cached one: ``repo update``
does not read the signed ``generated_at``. A registry can serve an old
index, or none, and hide newer versions. A target refuses a changed
tree publication whose generation is not higher than the one it applied
last, but the registry can keep serving an unchanged publication, and
the first sync accepts any generation.

An index names repositories, not the registry. An index signed for one
registry verifies on any other whose repository definition names the
same certificate.

``repo update`` is not measured. The register records upatch loads,
unloads and tree operations, not which index or package version a
target saw, and ``bpm list`` reports the target's own state.

``bpm install`` and ``bpm pull`` also take a direct
``oci://<registry>/<repository>:<tag>``. That path has no index: the
registry resolves the tag, and only the layer digest from that manifest
is checked. The kernel's signature check still applies to each upatch,
so the registry can choose only among artifacts a trusted key once
signed, old ones included.

Environment variables select the transport, and processes with runtime
authority honor them: ``BPM_OCI_SCHEME=http`` turns TLS off,
``BPM_OCI_CA_FILE`` adds a trust anchor, and libcurl's proxy variables
redirect traffic. The repository update and tree sync units read
``/etc/shirudo/bpm/environment``, which root can write. Signatures
still bind what a target loads, so this gives root the position of a
hostile registry.

On the operator host, ``shirudo bpm config update --base-package
oci://...`` without ``--file`` downloads the base package by tag, checks it
only against its manifest's layer digest, and runs the updater
commands of the Beefile inside it. Whoever can move that tag can run
commands on the operator host. Pass ``-f`` with a Beefile you control,
or a package file you built.

Related
-------

- :doc:`/operate/run/deliver-packages`
- :doc:`/upatches/publish/publishing`
- :doc:`/reference/formats/bpm-formats`
- :doc:`/reference/cli/bpm`
- :doc:`/reference/environment`
- :doc:`pqc` for the TLS policy
- :doc:`/security/threat-model` for the residual risks of delivery
