#!/usr/bin/python3
import zipfile
import hashlib
import io
from typing import Dict, Any, Tuple
from pathlib import Path, PurePath

from phantom.app import APP_SUCCESS, APP_ERROR
from phantom import vault
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import yara

import yara_config


class RetVal(tuple):
    def __new__(cls, val1, val2=None) -> Tuple[bool, Any]:
        return tuple.__new__(RetVal, (val1, val2))


class YaraConnector(BaseConnector):
    def __init__(self) -> None:
        super(YaraConnector, self).__init__()
        self._state = None
        self.state_dir: str = ""

    def _return_with_message(
        self,
        message: str = "",
        action_result: ActionResult = None,
        status: bool = APP_SUCCESS,
    ) -> RetVal:
        self.save_progress(message)
        return RetVal(action_result.set_status(status, message), None)

    def _fetch_yara_source(self, location: str = "") -> None:
        """
        Accept some location read from _reserved_environment_variables
        and download its contents.  This allows an asset to be comprised of
        multiple sources, store any URLs containing credentials as secrets
        and download all content
        """

        response = requests.get(location)
        if not response.ok:
            raise Exception(response.text)

        if self.get_action_identifier() == "test_connectivity":
            self.save_progress(f"Connected successfully to {location}")
            return

        if response.headers.get("Content-Type", "").find("application/zip") > -1:
            self.save_progress("Extracting downloaded zip")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip:
                zip.extractall(path=self.state_dir)

        if response.headers.get("Content-Type", "").find("text/plain") > -1:
            self.save_progress(f"Writing fetched file to {self.state_dir}")
            with open(
                PurePath(self.state_dir, location.split("/")[-1].split("?")[0]), "wb"
            ) as filename:
                filename.write(response.content)

    def _handle_update_sources(self) -> RetVal:
        """
        Doubles as test connectivity function.  _fetch_yara_source will short-circuit
        and return before overwriting any files.
        """

        action_result = self.add_action_result(ActionResult())
        if env_vars := self.get_config().get(
            "_reserved_environment_variables", {}
        ):
            for source in env_vars:
                location = env_vars.get(source, {}).get("value", None)
                try:
                    self._fetch_yara_source(location)
                except Exception as error:
                    message = f"Connection to {source}|{location} failed with {error}"
                    return self._return_with_message(message, action_result, APP_ERROR)
        else:
            message = (
                "No asset environment variables configured.  Add URL sources to fetch!"
            )
            return self._return_with_message(message, action_result, APP_ERROR)

        message = "Connected to all sources!"
        return self._return_with_message(message, action_result)

    def _handle_clear_sources(self, param) -> RetVal:
        action_result = self.add_action_result(ActionResult(dict(param)))
        import shutil

        for file in Path(PurePath(self.state_dir, param.get("path", ""))).iterdir():
            if not file.name.endswith("state.json"):
                try:
                    self.save_progress(f"Clearing structure at {file}")
                    action_result.add_data({"name": file.name, "directory": True})

                    shutil.rmtree(str(file))
                except NotADirectoryError:
                    file.unlink(missing_ok=True)
                    action_result.add_data({"name": file.name, "directory": False})
                except Exception as error:
                    return self._return_with_message(
                        f"Failed removing files -- {error}", action_result, APP_ERROR
                    )
        return self._return_with_message("Cleaned up!", action_result)

    def _handle_list_sources(self, param) -> RetVal:
        """
        List all directories in app's state_dir unless user has provided
        param.get("extension").  If it is provided, limit search to
        the files and directories matched in the provided glob.

        Optionally, set stat_info to get os.stat_result info for each file
        found.
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        extension: str = param.get("path", "**")
        for file in Path(self.state_dir).rglob(extension):
            file_info = {}
            if param.get("stat_info", False):
                file_info = Path(file).stat()
            action_result.add_data(
                {
                    **{"name": str(Path(file))},
                    **{
                        key: getattr(file_info, key)
                        for key in dir(file_info)
                        if key.startswith("st_")
                    },
                }
            )

        return self._return_with_message("Listed sources!", action_result)

    def _handle_yara_scan(self, param) -> RetVal:
        """
        Look up all files in self.state_dir found in provided yara_path, defaulting
        to all files in self.state_dir, something we may or may not want depending
        on the source that was downloaded.

        scan_dir is the target of our yara search. If not provided, we're expecting
        a container_id to use for looking up the contents of a vault for scanning.

        Optionally, set a boolean for whether or not the include directive should
        be allowed when yara compiles any specified files.
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        cached_ruleset = hashlib.blake2b(
            f"{param.get('yara_path', '**')}".encode()
        ).hexdigest()
        try:
            rules = yara.load(f"{self.state_dir}/{cached_ruleset}")
        except yara.Error as error:
            self.save_progress(error)
            self.save_progress("No cached compiled rule set found, compiling now...")
            try:
                rules = yara.compile(
                    filepaths={
                        file.name: str(file)
                        for file in Path(self.state_dir).rglob(
                            param.get("yara_path", "**")
                        )
                    },
                    includes=param.get("use_includes", False),
                )
                rules.save(f"{self.state_dir}/{cached_ruleset}")
            except NotImplementedError as error:
                self.save_progress("You cannot use non-relative path patterns here!")
                return self._return_with_message(str(error), action_result, APP_ERROR)

        # Sends param with user-provided inputs to dataclass and only initialize with those values defined
        # in the class signature.  Then, unpack to keyword arguments for set_config()
        yara.set_config(**vars(yara_config.YaraConfig.from_params((param))))

        # Prefer scan_dir if provided, falling back to the vault from event's container
        scan_dir: str = param.get(
            "scan_dir", vault.vault_info(container_id=self.get_container_id())
        )
        self.save_progress(f"Scanning {scan_dir} with loaded Yara rules")
        for file in Path(scan_dir).glob("**/*"):
            if not file.is_dir():
                try:
                    self.save_progress(f"Scanning {file}")
                    if matches := rules.match(
                        filepath=str(file.resolve()),
                        fast=param.get("fast_mode", False),
                        timeout=param.get("timeout", 60),
                    ):
                        for match in matches:
                            self.save_progress(f"Found match for {match.rule}")
                            action_result.add_data(
                                {
                                    "rule": match.rule,
                                    "namespace": match.namespace,
                                    "tags": match.tags,
                                    "meta": match.meta,
                                    "strings": match.strings,
                                    "file": str(file),
                                }
                            )
                except yara.TimeoutError:
                    message = f"Timeout when scanning {file}.  Specify a larger timeout and try again."
                    return self._return_with_message(message, action_result, APP_ERROR)

        return self._return_with_message(f"Finished scanning {scan_dir}", action_result)

    def handle_action(self, param: Dict[str, Any]) -> RetVal:
        ret_val = APP_SUCCESS

        action_id = self.get_action_identifier()
        self.save_progress(
            f"Executing action handler for: {action_id} with params {param}"
        )
        if action_id == "yara_scan":
            ret_val = self._handle_yara_scan(param)

        if action_id == "list_yara_sources":
            ret_val = self._handle_list_sources(param)

        if action_id == "clear_yara_sources":
            ret_val = self._handle_clear_sources(param)

        if action_id == "update_yara_sources":
            ret_val = self._handle_update_sources()

        if action_id == "test_connectivity":
            # Not a typo.  This will return early if running test_connectivity
            ret_val = self._handle_update_sources()

        return ret_val

    def initialize(self) -> bool:
        self._state = self.load_state()
        self.state_dir = self.get_state_dir()

        return APP_SUCCESS

    def finalize(self) -> bool:
        self.save_state(self._state)
        return APP_SUCCESS


def main():
    import argparse
    import json

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = f"{YaraConnector._get_phantom_base_url()}/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)  # nosec
            csrftoken = r.cookies.get("csrftoken", None)

            data = {
                "username": username,
                "password": password,
                "csrfmiddlewaretoken": csrftoken,
            }

            headers = {"Cookie": f"csrftoken={csrftoken}", "Referer": login_url}

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url, verify=False, data=data, headers=headers  # nosec
            )
            session_id = r2.cookies.get("sessionid")
        except Exception as e:
            print(f"Unable to get session id from the platform. Error: {e}")
            exit(1)

    with open(args.input_test_json) as filename:
        in_json = json.load(filename)
        print(json.dumps(in_json, indent=4))

        connector = YaraConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])  # type: ignore  # Pylance

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
