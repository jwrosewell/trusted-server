# Third party notices

Trusted Server is licensed under the Apache License 2.0. The full text is in
[LICENSE](LICENSE).

This file lists third party software that a Trusted Server deployment runs
alongside, where that software carries its own license and its own conditions.
Each entry says what the software is, who holds the copyright, which license it
is under, where its source can be obtained, and what we owe the people we give
it to.

Software listed here is not part of Trusted Server. It runs as its own program,
in its own container, and Trusted Server talks to it over HTTP. Nothing here is
compiled into, linked with, or bundled inside the Trusted Server binary.

---

## Ethical Ad Server

An advertising server that Trusted Server can ask for an ad. A deployment runs
it as a separate container, reached over HTTP on a private network, as set out
in [`deploy/eas/compose.yaml`](deploy/eas/compose.yaml) and
[`docs/guide/ethical-ad-server.md`](docs/guide/ethical-ad-server.md).

| Item | Value |
| --- | --- |
| Copyright | Read the Docs, Inc |
| License | GNU Affero General Public License version 3 (AGPL-3.0) |
| License text | [`licenses/AGPL-3.0.txt`](licenses/AGPL-3.0.txt) |
| Upstream source | https://github.com/readthedocs/ethical-ad-server |
| Mirror | https://github.com/jwrosewell/ethical-ad-server |

### Version in use

<!-- To move a deployment to a different version, change these two lines and
     nothing else in this file. If the version being run is a modified one,
     name the repository that holds the modification and the commit on that
     repository, because that is then the source that has to be offered. -->

- Repository: https://github.com/readthedocs/ethical-ad-server
- Commit: `62dafb55f7a4245df97f086633459b3309d41c44`

That commit is unmodified upstream code.
https://github.com/jwrosewell/ethical-ad-server is a public fork of the same
project, and its `main` branch is at the same commit, so the same source can be
obtained from either place. Verified against both repositories on 5 September
2026.

### Written offer of source

The complete source of the ad server described above, being the exact commit
named under "Version in use", is available to anyone, at no charge, from either
repository listed above. Both are public, and either satisfies AGPL-3.0 section
6(d), which allows the source to be offered from a network server other than
the one distributing the object code, including a server run by somebody else.

If neither URL reaches you, open an issue at
https://github.com/IABTechLab/trusted-server and ask for the source of the ad
server at the commit named above, and we will send it.

Anyone who receives the ad server from us also receives it under AGPL-3.0, and
its copyright and license notices must be kept intact and passed on.

### Why Trusted Server stays under the Apache License

The AGPL applies to the ad server. It does not reach across into Trusted
Server, because the two are separate and independent programs that are not
combined into one. They run as separate processes, in separate container
images, built from separate source trees, sharing no code and no library, and
they talk to each other over HTTP. AGPL-3.0 section 5 covers exactly this
arrangement: putting a covered work alongside other works in an aggregate does
not make the license apply to the other parts.

Three things would change that, so none of them should be done without advice:

- Compiling or linking any part of the ad server into a Trusted Server binary.
- Building one container image that contains both programs, or otherwise
  shipping them as a single work rather than as two programs an operator runs
  together.
- Modifying the ad server. That is allowed, and the modified version stays
  AGPL-3.0, but section 13 then requires that people who interact with it over
  a network are offered its source. A modification kept in a public repository
  meets that, which is what the mirror above is for, as long as the "Version in
  use" block names the repository and commit that is actually running.

### The ad server's own dependencies

The ad server brings its own Python and JavaScript dependencies, each under its
own license. They are listed in that project's `pyproject.toml`, `uv.lock` and
`package-lock.json`, and they are installed into the ad server's image by the
ad server's own build. They are not redistributed by this project.
