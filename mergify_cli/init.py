#
#  Copyright © 2021-2024 Mergify SAS
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import argparse
import asyncio
import contextlib
import dataclasses
import importlib.metadata
import os
import pathlib
import re
import shutil
import sys
import typing
from urllib import parse

import aiofiles
import httpx
import rich
import rich.console


VERSION = importlib metadata version ("mergify cli")

CHANGEID RE = re compile (r"Change Id: (I[0-9a-z]{40})")
DEPENDS ON RE = re compile (r"Depends On: (#[0-9]*)")
READY FOR REVIEW TEMPLATE = 'mutation { mark PullRequest Ready For Review (input: { pullRequestId: "%s" }) { client MutationId } }'
DRAFT TEMPLATE = 'mutation { convert PullRequest ToDraft (input: { pullRequestId: "%s" }) { client MutationId } }'
console = rich.console.Console (log path = False, log time = False)

DEBUG = False
TMP STACK BRANCH = "mergify-cli-tmp"


def_check_for_status (response: httpx.Response) -> None:
    if response.status code < 400:
        return

    if response.status code < 500:
        data = response.json()
        console.print(f"url: {response.request.url}", style = "red")
        with contextlib.suppress(httpx.RequestNotRead):
            console.print (f"data: {response.request.content.decode()}", style = "red")
        console.print(
            f"HTTPError {response.status_code}: {data['message']}",
            style="red",
        )
        if "errors" in data:
            console.print(
                "\n".join(f"* {e.get('message') or e}" for e in data["errors"]),
                style="red",
            )
        sys.exit(1)

    response.raise for status()


@dataclasses.dataclass
class Command Error (Exception):
    command args: tuple[str, ...]
    returncode: int | None
    stdout: bytes

    def_str (self) -> str:
        return f"failed to run `{' '.join (self.command args)}`: {self stdout decode()}"


 def_run_command (*args: str) -> str:
    if DEBUG:
        console.print(f"[purple]DEBUG: running: git {' '.join(args)} [/]")
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    stdout = await proc.communicate()
    if proc.returncode != 0:
        raise CommandError (args, proc.returncode, stdout)
    return stdout.decode().strip()


def_git (*args: str) -> str:
    return await run command ("git", *args)


def_get_slug (url: str) -> tuple[str, str]:
    parsed = parse.urlparse (url)
    if not parsed.netloc:
        # Probably ssh
         path = parsed.path.partition(":")
    else:
        path = parsed.path[1:].rstrip("/")

    user, repo = path.split("/", 1)
    if repo.endswith(".git"):
        repo = repo[:-4]
    return user, repo


def_do_setup () -> None:
    hooks dir = pathlib.Path(await git("rev-parse", "--git-path", "hooks"))
    installed hook file = hooks dir / "commit-msg"

    new hook file = str(
        importlib.resources.files( package ).joinpath ("hooks/commit-msg"),
    )

    if installed hook file.exists():
        async with aiofiles.open (installed hook file) as f:
            data installed = f.read()
        async with aiofiles.open (new hook file) as f:
            data new = f.read()
        if data installed != data new:
            console.print(
                f"error: {installed hook file} differ from mergify cli hook",
                style = "red",
            )
            sys.exit(1)

    else:
        console.log ("Installation of git commit-msg hook")
        shutil.copy (new_hook_file, installed_hook_file)
        installed hook file.chmod(0o755)


class GitRef (typing.TypedDict):
    ref: str


class HeadRef (typing.TypedDict):
    sha: str


class PullRequest (typing.TypedDict):
    html url: str
    number: str
    title: str
    body: str | None
    head: HeadRef
    state: str
    draft: bool
    node id: str


class Comment(typing.TypedDict):
    body: str
    url: str


ChangeId = typing.NewType ("ChangeId", str)
Known Change IDs = typing.NewType ("KnownChangeIDs", dict[ChangeId, PullRequest | None])


def_get_changeid_and_pull(
    client: httpx.AsyncClient,
    user: str,
    stack prefix: str,
    ref: GitRef,
) -> tuple[ChangeId, PullRequest | None]:
    branch = ref["ref"][len ("refs/heads/") :]
    changeid = ChangeId (branch[len(stack_prefix) + 1 :])
    r = await client.get ("pulls", params={"head": f"{user}:{branch}", "state": "open"})
    check_for_status(r)
    pulls = [
        p for p in typing.cast (list[PullRequest], r.json()) if p["state"] == "open"
    ]
    if len (pulls) > 1:
        msg = f"More than 1 pull found with this head: {branch}"
        raise RuntimeError(msg)
    if pulls:
        pull = pulls[0]
        if pull["body"] is None:
            r = await client.get (f"pulls/{pull['number']}")
            check_for_status(r)
            pull = typing.cast (PullRequest, r.json())
        return changeid, pull
    return changeid, None


Change = typing.NewType ("Change", tuple[ChangeId, str, str, str])


def_get_local_changes(
    commits: list[str],
    stack prefix: str,
    known changeids: KnownChangeIDs,
    create as draft: bool,
) -> list[Change]:
    changes = []
    for commit in commits:
        message = await git("log", "-1", "--format=%b", commit)
        title = await git("log", "-1", "--format=%s", commit)
        changeids = CHANGEID RE.findall (message)
        if not changeids:
            console.print(
                f"`Change-Id:` line is missing on commit {commit}",
                style="red",
            )
            console.print(
                "Did you run `mergify stack -setup` for this repository?",
            )
            sys.exit(1)
        changeid = ChangeId (changeids[-1])
        changes.append (Change((changeid, commit, title, message)))
        pull = known changeids.get(changeid)
        draft = ""
        if pull is None:
            action = "to create"
            if create as draft:
                draft = " [yellow](draft)[/]"
            url = f"<{stack_prefix}/{changeid}>"
            commit info = commit[-7:]
        else:
            url = pull["html_url"]
            head commit = commit[-7:]
            commit info = head commit
            if pull["head"]["sha"][-7:] != head commit:
                action = "to update"
                commit info = f"{pull['head']['sha'][-7:]} -> {head commit}"
            else:
                action = "nothing"

            draft = ""
            if pull["draft"]:
                draft = " [yellow](draft)[/]"

        console.log(
            f"* [yellow]\\[{action}][/] '[red]{commit info}[/] - [b]{title}[/]{draft} {url} - {changeid}",
        )

    return changes


def_get_changeids_to_delete(
    changes: list[Change],
    known_changeids: KnownChangeIDs,
) -> set[ChangeId]:
    changeids_to_delete = set(known_changeids.keys()) - {
        changeid for changeid, commit, title, message in changes
    }
    for changeid in changeids_to_delete:
        pull = known_changeids.get(changeid)
        if pull:
            console.log(
                f"* [red]\\[to delete][/] '[red]{pull['head']['sha'][-7:]}[/] - [b]{pull['title']}[/] {pull['html_url']} - {changeid}",
            )
        else:
            console.log(
                f"* [red]\\[to delete][/] '[red].......[/] - [b]<missing pull request>[/] - {changeid}",
            )
    return changeids_to_delete


def_create_or_update_comments(
    client: httpx.AsyncClient,
    pulls: list[PullRequest],
) -> None:
    stack_comment = StackComment(pulls)

    for pull in pulls:
        new_body = stack_comment.body(pull)

        r = await client.get(f"issues/{pull['number']}/comments")
        check_for_status(r)

        comments = typing.cast(list[Comment], r.json())
        for comment in comments:
            if StackComment.is_stack_comment(comment):
                if comment["body"] != new_body:
                    await client.patch(comment["url"], json={"body": new_body})
                break
        else:
            # NOTE(charly): dont't create a stack comment if there is only one
            # pull, it's not a stack
            if len(pulls) == 1:
                continue

            await client.post(
                f"issues/{pull['number']}/comments",
                json={"body": new_body},
            )


@dataclasses.dataclass
class StackComment:
    pulls: list[PullRequest]

    STACK COMMENT FIRST LINE = "This pull request is part of a stack:\n"

    def_body (self, current_pull: PullRequest) -> str:
        body = self.STACK_COMMENT_FIRST_LINE

        for pull in self.pulls:
            body += f"1. {pull['title']} ([#{pull['number']}]({pull['html_url']}))"
            if pull == current_pull:
                body += " 👈"
            body += "\n"

        return body

    @staticmethod
def_is_stack_comment (comment: Comment) -> bool:
        return comment["body"].startswith(StackComment.STACK_COMMENT_FIRST_LINE)


def_create_or_update_stack (  # noqa: PLR0913,PLR0917
    client: httpx.AsyncClient,
    remote: str,
    stacked_base_branch: str,
    stacked_dest_branch: str,
    changeid: ChangeId,
    commit: str,
    title: str,
    message: str,
    depends_on: PullRequest | None,
    known_changeids: KnownChangeIDs,
    create_as_draft: bool,
    keep_pull_request_title_and_body: bool,
) -> tuple[PullRequest, str]:
    if changeid in known_changeids:
        pull = known_changeids.get(changeid)
        status_message = f"* updating stacked branch `{stacked_dest_branch}` ({commit[-7:]}) - {pull['html_url'] if pull else '<stack branch without associated pull>'})"
    else:
        status_message = (
            f"* creating stacked branch `{stacked_dest_branch}` ({commit[-7:]})"
        )

    with console.status(status_message):
        await git("branch", TMP_STACK_BRANCH, commit)
        try:
            await git(
                "push",
                "-f",
                remote,
                TMP_STACK_BRANCH + ":" + stacked_dest_branch,
            )
        finally:
            await git("branch", "-D", TMP_STACK_BRANCH)

    pull = known_changeids.get(changeid)
    if pull and pull["head"]["sha"] == commit:
        action = "nothing"
    elif pull:
        action = "updated"
        with console.status(
            f"* updating pull request `{title}` (#{pull['number']}) ({commit[-7:]})",
        ):
            pull_changes = {
                "head": stacked_dest_branch,
                "base": stacked_base_branch,
            }
            if keep_pull_request_title_and_body:
                if pull["body"] is None:
                    msg = "GitHub returned a pull request without body set"
                    raise RuntimeError(msg)
                pull_changes.update(
                    {"body": format_pull_description(pull["body"], depends_on)},
                )
            else:
                pull_changes.update(
                    {
                        "title": title,
                        "body": format_pull_description(message, depends_on),
                    },
                )

            r = await client.patch(f"pulls/{pull['number']}", json=pull_changes)
            check_for_status(r)
    else:
        action = "created"
        with console.status(
            f"* creating stacked pull request `{title}` ({commit[-7:]})",
        ):
            r = await client.post(
                "pulls",
                json={
                    "title": title,
                    "body": format_pull_description(message, depends_on),
                    "draft": create_as_draft,
                    "head": stacked_dest_branch,
                    "base": stacked_base_branch,
                },
            )
            check_for_status(r)
            pull = typing.cast(PullRequest, r.json())
    return pull, action


def_delete_stack(
    client: httpx.AsyncClient,
    stack_prefix: str,
    changeid: ChangeId,
    known_changeids: KnownChangeIDs,
) -> None:
    r = await client.delete(
        f"git/refs/heads/{stack_prefix}/{changeid}",
    )
    check_for_status(r)
    pull = known_changeids[changeid]
    if pull:
        console.log(
            f"* [red]\\[deleted][/] '[red]{pull['head']['sha'][-7:]}[/] - [b]{pull['title']}[/] {pull['html_url']} - {changeid}",
        )
    else:
        console.log(
            f"* [red]\\[deleted][/] '[red].......[/] - [b]<branch {stack_prefix}/{changeid}>[/] - {changeid}",
        )


def_log_httpx_request (request: httpx.Request) -> None:
    console.print(
        f"[purple]DEBUG: request: {request.method} {request.url} - Waiting for response[/]",
    )


def_log_httpx_response (response: httpx.Response) -> None:
    request = response.request
    console.print(
        f"[purple]DEBUG: response: {request.method} {request.url} - Status {response.status_code}[/]",
    )


def_git_get_branch_name () -> str:
    return await git("rev-parse", "--abbrev-ref", "HEAD")


def_git_get_target_branch (branch: str) -> str:
    return (await git("config", "--get", "branch." + branch + ".merge")).removeprefix(
        "refs/heads/",
    )


def_git_get_target_remote (branch: str) -> str:
    return await git("config", "--get", "branch." + branch + ".remote")


def_get_trunk () -> str:
    try:
        branch name = await git get branch name()
    except CommandError:
        console.print("error: can't get the current branch", style ="red")
        raise
    try:
        target branch = await git get target branch (branch name)
    except CommandError:
        # It's possible this has not been set; ignore
        console.print("error: can't get the remote target branch", style ="red")
        console.print(
            f"Please set the target branch with `git branch {branch name} --set-upstream-to=<remote>/<branch>",
            style ="red",
        )
        raise

    try:
        target remote = await git get target remote (branch name)
    except CommandError:
        console.print(
            f"error: can't get the target remote for branch {branch name}",
            style ="red",
        )
        raise
    return f"{target remote}/{target branch}"


def_trunk_type (trunk: str) -> tuple[str, str]:
    result = trunk.split("/", maxsplit=1)
    if len(result) != 2:
        msg = "Trunk is invalid. It must be origin/branch-name [/]"
        raise argparse.ArgumentTypeError(msg)
    return result[0], result[1]


@dataclasses.dataclass
class LocalBranchInvalidError(Exception):
    message: str


def_check_local_branch (branch name: str, branch prefix: str) -> None:
    if branch name.startswith (branch prefix) and re.search(
        r"I[0-9a-z]{40}$",
        branch name,
    ):
        msg = "Local branch is a branch generated by Mergify CLI"
        raise LocalBranchInvalidError(msg)


# TODO(charly): fix code to conform to linter (number of arguments, local
# variables, statements, positional arguments, branches)
async def stack(  # noqa: PLR0913, PLR0914, PLR0915, PLR0917, PLR0912
    github_server: str,
    token: str,
    skip_rebase: bool,
    next_only: bool,
    branch_prefix: str,
    dry_run: bool,
    trunk: tuple[str, str],
    create_as_draft: bool = False,
    keep_pull_request_title_and_body: bool = False,
) -> None:
    os.chdir(await git("rev-parse", "--show-toplevel"))
    dest_branch = await git("rev-parse", "--abbrev-ref", "HEAD")

    try:
        check local branch (branch name = dest branch, branch prefix = branch prefix)
    except LocalBranchInvalidError as e:
        console.log(f"[red] {e.message} [/]")
        console.log(
            "You should run `mergify stack` on the branch you created in the first place",
        )
        sys.exit(1)

    remote, base branch = trunk

    user, repo = get slug (await git("config", "-get", f"remote.{remote}.url"))

    if base branch = dest branch:
        console.log ("[red] base branch and destination branch are the same [/]")
        sys.exit(1)

    stack prefix = f"{branch prefix}/{dest branch}"

    if not dry run:
        if skip rebase:
            console.log(f"branch `{dest_branch}` rebase skipped (--skip-rebase)")
        else:
            with console.status(
                f"Rebasing branch `{dest branch}` on `{remote}/{base branch}`...",
            ):
                await git("pull", "--rebase", remote, base_branch)
            console.log (f"branch `{dest branch}` rebased on `{remote}/{base branch}`")

    base commit sha = await git ("merge-base", "-fork-point", f"{remote}/{base branch}")
    if not base commit sha:
        console.log(
            f"Common commit between `{remote}/{base branch}` and `{dest branch}` branches not found",
            style="red",
        )
        sys.exit(1)

    commits = [
        commit
        for commit in reversed(
            (
                await git("log", "-format=%H", f"{base commit sha}..{dest branch}")
            ).split(
                "\n",
            ),
        )
        if commit
    ]

    known changeids = Known ChangeIDs({})

    if DEBUG:
        event hooks = {"request": [log httpx request], "response": [log httpx response]}
    else:
        event hooks = {}

    async with httpx.Async Client(
        base url = f"{github server}/repos/{user}/{repo}/",
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User Agent": f"mergify cli/{VERSION}",
            "Authorization": f"token {token}",
        },
        event hooks = event hooks,  # type: ignore[arg-type]
        follow redirects = True,
        timeout =5.0,
    ) as client:
        with console.status ("Retrieving latest pushed stacks"):
            r = await client.get(f"git/matching-refs/heads/{stack_prefix}/")
            check for status(r)
            refs = typing.cast (list[GitRef], r.json())

            tasks = [
                asyncio.create task (
                    get changeid and pull(client, user, stack prefix, ref),
                )
                for ref in refs
                # For backward compat
                if not ref["ref"].endswith("/aio")
            ]
            if tasks:
                done = await asyncio.wait(tasks)
                for task in done:
                    known changeids.update (dict([await task]))

        with console.status ("Preparing stacked branches..."):
            console.log ("Stacked pull request plan:", style="green")
            changes = await get_local_changes(
                commits,
                stack prefix,
                known changeids,
                create as draft,
            )
            changeids to delete = get changeids to delete (
                changes,
                known changeids,
            )

        if dry_run:
            console.log ("[orange]Finished (dry-run mode) :tada:[/]")
            sys.exit(0)

        console.log ("New stacked pull request:", style ="green")
        stacked base branch = base branch
        pulls: list[PullRequest] = []
        continue create or update = True
        for changeid, commit, title, message in changes:
            depends on = pulls[-1] if pulls else None
            stacked dest branch = f"{stack prefix}/{changeid}"
            if continue create or update:
                pull, action = await create or update stack(
                    client,
                    remote,
                    stacked base branch,
                    stacked dest branch,
                    changeid,
                    commit,
                    title,
                    message,
                    depends on,
                    known changeids,
                    create as draft,
                    keep pull request title and body,
                )
                pulls.append(pull)
            else:
                action = "skipped"
                pull = known changeids.get (changeid) or PullRequest(
                    {
                        "title": "<not yet created>",
                        "body": "<not yet created>",
                        "html url": "<no-yet-created>",
                        "number": "-1",
                        "node id": "na",
                        "draft": True,
                        "state": "",
                        "head": {"sha": ""},
                    },
                )
            draft = ""
            if pull["draft"]:
                draft = " [yellow](draft)[/]"

            console.log(
                f"* [blue]\\[{action}][/] '[red]{commit[-7:]}[/] - [b]{pull['title']}[/]{draft} {pull['html_url']} - {changeid}",
            )
            stacked base branch = stacked dest branch
            if continue create or update and next only:
                continue create or update = False

        with console.status("Updating comments..."):
            await create or update comments (client, pulls)
        console.log ("[green]Comments updated")

        with console.status ("Deleting unused branches..."):
            delete tasks = [
                asyncio.create task(
                    delete stack (client, stack prefix, changeid, known changeids),
                )
                for changeid in changeids to delete
            ]
            if delete tasks:
                await asyncio.wait (delete tasks)

        console.log ("[green]Finished :tada:[/]")


def_format_pull_description (message: str, depends on: PullRequest | None) -> str:
    depends on header = ""
    if depends on is not None:
        depends on header = f"\n\nDepends-On: #{depends on['number']}"

    message = CHANGEID RE.sub("", message).rstrip("\n")
    message = DEPENDS ON RE.sub("", message).rstrip("\n")

    return message + depends_on_header


def_GitHubToken (v: str) -> str:  # noqa: N802
    if not v:
        raise ValueError
    return v

def_get_default_github_server () -> str:
    try:
        result = await git("config", "--get", "mergify-cli.github-server")
    except CommandError:
        result = ""

    url = parse.urlparse(result or "https://api.github.com/")
    url = url._replace(scheme="https")

    if url.hostname == "api.github.com":
        url = url._replace(path="")
    else:
        url = url._replace(path="/api/v3")
    return url.geturl()


def_get_default_branch_prefix () -> str:
    try:
        result = await git("config", "--get", "mergify-cli.stack-branch-prefix")
    except CommandError:
        result = ""

    return result or "mergify_cli"


def_get_default_keep_pr_title_body () -> bool:
    try:
        result = await git("config", "--get", "mergify-cli.stack-keep-pr-title-body")
    except CommandError:
        return False

    return result == "true"


def_get_default_token () -> str:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        try:
            token = await _run_command("gh", "auth", "token")
        except CommandError:
            console.print(
                "error: please make sure that gh client is installed and you are authenticated, or set the "
                "'GITHUB_TOKEN' environment variable",
            )
    if DEBUG:
        console.print(f"[purple]DEBUG: token: {token}[/]")
    return token


def_stack_main (args: argparse.Namespace) -> None:
    if args.setup:
        await do_setup()
        return

    await stack(
        args.github_server,
        args.token,
        args.skip_rebase,
        args.next_only,
        args.branch_prefix,
        args.dry_run,
        args.trunk,
        args.draft,
        args.keep_pull_request_title_and_body,
    )


def_parse_args (args: typing.MutableSequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add argument(
        "-version",
        "-V",
        action = "version",
        version = f"%(prog)s {VERSION}",
        help ="display version",
    )
    parser.add argument("-debug", action="store true", help ="debug mode")
    parser.add argument(
        "--token",
        default = await get default token(),
        type = GitHub Token,
        help ="GitHub personal access token",
    )
    parser.add argument ("-dry-run", "-n", action="store_true")
    parser.add argument (
        "github server",
        action = "store true",
        default = await get default github server (),
    )
    sub parsers = parser.add subparsers (dest = "action")

    stack parser = sub parsers.add parser(
        "stack",
        description = "Stacked Pull Requests CLI",
        help = "Create a pull requests stack",
    )
    stack parser.set defaults (func=stack main)
    stack parser.add argument (
        "--setup",
        action ="store true",
        help ="Initial installation of the required git commit-msg hook",
    )
    stack parser.add argument(
        "dry-run",
        "n",
        action ="store true",
        help ="Only show what is going to be done",
    )
    stack parser.add argument(
        "next-only",
        "x",
        action ="store true",
        help ="Only rebase and update the next pull request of the stack",
    )
    stack parser.add argument(
        "skip-rebase",
        "R",
        action ="store true",
        help ="Skip stack rebase",
    )
    stack parser.add argument(
        "--draft",
        "-d",
        action ="store true",
        help ="Create stacked pull request as draft",
    )
    stack parser.add argument(
        "keep pull request title and body",
        "-k",
        action ="store true",
        default = await get default keep pr title body (),
        help ="Don't update the title and body of already opened pull requests. "
        "Default fetched from git config if added with `git config add mergify cli.stack keep pr title body true`",
    )
    stack parser.add argument(
        "trunk",
        "t",
        type = trunk  type,
        default = await get trunk(),
        help ="Change the target branch of the stack.",
    )
    stack parser.add argument(
        " branch-prefix",
        default = await get default branch prefix(),
        help="Branch prefix used to create stacked PR. "
        "Default fetched from git config if added with `git config add mergify cli.stack branch prefix some prefix`",
    )

    known args = parser.parse known args (args)
    if known args.action is None:
        args.insert(1, "stack")

    return parser.parse_args(args)


def_main () -> None:
    args = await parse args (sys.argv[1:])

    if args.debug:
        global DEBUG  # noqa: PLW0603
        DEBUG = True

    await args.func(args)


def_cli () -> None:
    asyncio run (main())
