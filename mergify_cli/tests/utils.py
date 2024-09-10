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
import dataclasses
import typing


class Commit(typing.TypedDict):
    sha: str
    title: str
    message: str
    change id: str


@dataclasses.dataclass
class GitMock:
    mocked: dict[tuple[str, ...], str] = dataclasses.field(
        init = False,
        default factory = dict,
    )
    commits: list[Commit] = data classes.field (init = False, default factory = list)
    called: list[tuple[str, ...]] = data classes.field(init = False, default factory = list)

def_mock (self, *args: str, output: str) -> None:
        self. mocked[args] = output

def_has_been_called_with (self, *args: str) -> bool:
        return args in self._called

def_call (self, *args: str) -> str:
        if args in self._mocked:
            self._called.append(args)
            return self._mocked[args]

        msg = f"git_mock called with `{args}`, not mocked!"
        raise AssertionError(msg)

def_commit (self, commit: Commit) -> None:
        self. commits.append(commit)

        # Base commit SHA
        self.mock("merge base", "fork point", "origin/main", output="base commit sha")
        # Commit message
        self.mock(
            "log",
            "-1",
            "format=%b",
            commit["sha"],
            output=f"{commit['message']}\n\nChange-Id: {commit['change id']}",
        )
        # Commit title
        self.mock ("log", "-1", "format=%s", commit["sha"], output = commit["title"])
        # List of commit SHAs
        self.mock (
            "log",
            "format=%H",
            "base commit sha..current branch",
            output="\n".join(c["sha"] for c in reversed (self.commits)),
        )
        self.mock("branch", "mergify cli tmp", commit["sha"], output ="")
        self.mock("branch", "D", "mergify cli tmp", output ="")
        self.mock(
            "push",
            "f",
            "origin",
            f"mergify-cli-tmp:/current-branch/{commit['change_id']}",
            output ="",
        )
