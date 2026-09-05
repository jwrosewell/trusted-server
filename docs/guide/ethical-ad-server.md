# Running the Ethical Ad Server

Trusted Server can ask the Ethical Ad Server for an ad. The two are separate
programs. You run them as two containers that talk to each other over HTTP, and
this page is how a publisher gets that pair running, what to set up in the ad
server once it is running, and where the ad server's source comes from.

The compose file that runs the pair is `deploy/eas/compose.yaml` in this
repository.

## What each container does

| Container   | What it is                                             | Reachable from                      |
| ----------- | ------------------------------------------------------ | ----------------------------------- |
| `appliance` | Trusted Server itself, running the native Axum adapter | your readers, on the published port |
| `eas`       | the Ethical Ad Server, a Django application            | the appliance only                  |
| `postgres`  | the ad server's database                               | the ad server only                  |
| `redis`     | the ad server's queue and cache                        | the ad server only                  |

The appliance is the only service open to the outside. The ad server sits on a
private network with the database and the cache, and the appliance reaches it
at `http://eas:5000`. Readers never talk to the ad server, which is the point:
the ad request is made server to server, from your machine, and the ad server's
own documentation describes that as the way it is meant to be used.

## Ports that matter

| Port                              | What it is                     | Change it with      |
| --------------------------------- | ------------------------------ | ------------------- |
| `8080` on the host                | the appliance, open to readers | `TS_APPLIANCE_PORT` |
| `5001` on the host, loopback only | the ad server's admin pages    | `EAS_ADMIN_PORT`    |
| `5000` inside the network         | the ad server's API and admin  | fixed               |

The admin port is published on `127.0.0.1` only, so the admin pages are
reachable from the machine running the stack and from nowhere else. The ad
server's sample settings assume port 5000 on the host, which is where
`MEDIA_URL` points in its `.envs/local/django.sample`, so if you change
`EAS_ADMIN_PORT` then change `MEDIA_URL` to match, or the image previews in the
admin pages will not load.

## Before the first run

**Get the ad server's source.** Clone it next to this repository, as
`ethical-ad-server`, or put it wherever you like and set `EAS_SOURCE` to that
path. The compose file builds the ad server's image from that checkout using
the ad server's own Dockerfile, and mounts the checkout into the container,
because that Dockerfile installs the dependencies but does not copy the
application into the image. The code that runs is therefore the code in your
checkout, which is also the copy of the source you are entitled to read and
pass on.

```bash
git clone https://github.com/jwrosewell/ethical-ad-server.git
```

**On Windows, check the line endings first.** Git's `core.autocrlf` is normally
on, and it rewrites the ad server's container start scripts to Windows line
endings. The container then dies immediately with:

```
exec /start: no such file or directory
```

The file is there. The shebang has become `#!/bin/bash\r`, and there is no
program of that name. Clone with `git -c core.autocrlf=false clone ...`, or fix
an existing checkout by converting the files under `docker-compose/` to Unix
line endings. This affects Windows hosts only.

**Create the ad server's settings file.** The ad server ships a sample and
ignores the real one, so it does not exist in a fresh checkout and compose will
stop and name it:

```bash
cd ethical-ad-server
cp .envs/local/django.sample .envs/local/django
```

## Starting the pair

From the root of this repository:

```bash
# Build the ad server's images once. This takes a while.
docker compose -f deploy/eas/compose.yaml build eas postgres

# Bring up the database and the cache first.
docker compose -f deploy/eas/compose.yaml up -d postgres redis

# Create the ad server's database tables. The middle command works around an
# upstream defect, explained below. Run all three, in this order.
docker compose -f deploy/eas/compose.yaml run --rm eas uv run ./manage.py migrate
docker compose -f deploy/eas/compose.yaml run --rm eas uv run ./manage.py migrate adserver_auth 0011 --fake
docker compose -f deploy/eas/compose.yaml run --rm eas uv run ./manage.py migrate

# An account to sign in to the admin pages with.
docker compose -f deploy/eas/compose.yaml run --rm eas uv run ./manage.py createsuperuser

# Start the pair.
docker compose -f deploy/eas/compose.yaml up -d
```

The Django development server takes about twenty seconds to accept connections
after the last command returns, so a request made straight away is refused
rather than answered with an error.

### Why the first migrate command fails

It stops on this, on a brand new database:

```
django.db.utils.ProgrammingError: relation
"adserver_auth_user_adver_user_id_advertiser_id_5cfd9e2e_uniq" already exists
  Applying adserver_auth.0011_alter_useradvertisermember_unique_together...
```

Migration `0009_user_advertiser_publisher_roles` adopts a table that Django had
already created for a many to many field, without touching the database, and
that table already carries the unique constraint. Migration `0011` then tries to
create the same constraint again under the same name. Marking `0011` as applied
without running it, which is what `--fake` does, is correct here because the
database already contains exactly what that migration wants. The third command
then applies everything after it.

This is a defect in the ad server, not in this configuration, and it is not
specific to Windows.

## What to set up in the ad server

Sign in to `http://127.0.0.1:5001/admin/` and create the following. All of it
lives in the ad server's own database, and none of it is Trusted Server
configuration.

1. **The site domain.** Under Sites, set the domain of the one existing site.
   Every click and view URL the ad server returns is built from it, so until it
   is right those URLs point at `example.com`. Set it to the address readers
   reach, which is the appliance, not the ad server.
2. **A publisher record.** This is the account ads are requested for, and the
   request names it by slug. Set `unauthed ad decisions` if the appliance will
   call without credentials on a private network, or leave it off and create an
   API token for a user attached to the publisher. Set `send bid rate` if you
   want the price back on the decision, which is what an auction needs.
3. **An ad type.** The request names an ad type by slug and the ad server holds
   the size on that record, so there is no width or height in the request
   itself. Give the ad type a template. The default one renders the tracking
   pixel or the creative but not both, and it leaves out the words entirely for
   any ad written with a headline and body rather than the old free HTML field.
4. **An advertiser, a campaign and a CPM flight.** The flight is the ad buy: a
   price per thousand impressions, a number of impressions sold, and any
   targeting. Make the campaign type `paid` if you intend to request paid ads.
5. **One or more advertisements on that flight**, each attached to the ad type
   you created.

Ask the ad server for a decision and you will get an ad back once all five
exist. Until then it answers `{}` with HTTP 200, which means "no ad this time"
and is not an error.

### Tell the ad server where the reader is

The appliance makes the request, so without help every ad request looks as
though it came from the appliance. Two ways round it, and they can both be
used:

- Put the reader's address in `user_ip` and their browser's User-Agent in
  `user_ua` in the request body. The body wins over anything else.
- Set `ADSERVER_IPADDRESS_MIDDLEWARE=adserver.middleware.XForwardedForMiddleware`
  in the ad server's settings file, so it reads the address from the
  `X-Forwarded-For` header. The ad server's own documentation warns that this
  should only be on where that header is guaranteed by whatever sits in front,
  because otherwise anyone can claim any address. Behind the appliance, on the
  private network in this compose file, it is.

## Checking it works

The ad server answers on the private network under the name `eas`, so ask from
inside the appliance's own image:

```bash
docker compose -f deploy/eas/compose.yaml run --rm --no-deps --entrypoint curl appliance \
  -sS -o /dev/null -w "%{http_code}\n" http://eas:5000/
```

A `302` is the ad server redirecting to its login page, which means it is up.

Then ask for a decision, using the publisher slug and ad type slug you created:

```bash
docker compose -f deploy/eas/compose.yaml run --rm --no-deps --entrypoint curl appliance \
  -sS -X POST -H "Content-Type: application/json" \
  -d '{"publisher":"example-publisher","placements":[{"div_id":"ad-div-1","ad_type":"example-ad-v1","priority":10}]}' \
  http://eas:5000/api/v1/decision/
```

What comes back tells you where you are:

| Response                               | What it means                                   |
| -------------------------------------- | ----------------------------------------------- |
| `{}` with HTTP 200                     | no ad matched, everything else is working       |
| an object with `id`, `text` and `link` | an ad was served                                |
| `{"publisher":["Invalid publisher"]}`  | no publisher with that slug                     |
| an authentication error                | `unauthed ad decisions` is off, so send a token |

An unknown ad type is not an error. The ad server accepts any string there and
answers `{}`, so check the slug by eye if nothing ever fills.

### When the appliance answers nothing

If the appliance's published port accepts the connection and then returns an
empty reply, the process inside is listening on container loopback rather than
on every interface. The compose file sets `EDGEZERO__ADAPTER__HOST` to
`0.0.0.0` for exactly this reason. An appliance image whose adapter does not
pass that setting through will stay silent on the published port however the
port is mapped, so check the appliance image before looking anywhere else.

## Stopping and starting again

```bash
# Stop, keeping the database and the appliance's stored state.
docker compose -f deploy/eas/compose.yaml down

# Stop and throw away both.
docker compose -f deploy/eas/compose.yaml down --volumes
```

The appliance's volume holds Edge Cookie identity and consent state, and the
database volume holds the ad server's records and its reporting. Removing them
loses a reader's stored consent decision, so `--volumes` is not something to
reach for casually.

## The license position

**What you receive.** Two programs under two licenses. Trusted Server is under
the Apache License 2.0. The Ethical Ad Server is under the GNU Affero General
Public License version 3, and it stays under that license, whoever runs it. The
two are separate and independent programs: separate images, separate processes,
separate source, no shared code, talking over HTTP. That is an aggregate in the
words of AGPL-3.0 section 5, so the ad server's license covers the ad server and
does not reach across into Trusted Server. If you pass the ad server on to
anybody else, keep its copyright and license notices intact, pass on the AGPL
text with it, and make its source available to whoever you gave it to. The
license text is in `licenses/AGPL-3.0.txt` in this repository, and the notice
covering it is in `THIRD-PARTY-NOTICES.md` beside it.

**Where the source is.** The ad server's source is published, in full and at no
charge, at https://github.com/readthedocs/ethical-ad-server, and the same source
is mirrored at https://github.com/jwrosewell/ethical-ad-server. The exact commit
a deployment runs is recorded under "Version in use" in
`THIRD-PARTY-NOTICES.md`. You will also have a copy on disk, because the
compose file runs the ad server from a checkout rather than from a sealed
image. One thing to know if you change
the ad server: your modified version is still AGPL-3.0, and section 13 of that
license says people who use it across a network must be offered its source, so
publish your changes somewhere they can reach and record that place and commit
in the notices file.

## Find out more

- https://github.com/IABTechLab/trusted-server
- https://github.com/readthedocs/ethical-ad-server
- https://github.com/jwrosewell/ethical-ad-server
- https://ethical-ad-server.readthedocs.io
- https://www.gnu.org/licenses/agpl-3.0.html
