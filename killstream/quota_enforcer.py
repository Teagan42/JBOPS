import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import httpx
from aiofile import AIOFile

TAUTULLI_ENDPOINT = "/api/v2"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enforces weekly screen time quota for Plex users via Tautulli + Patreon."
    )
    parser.add_argument("--config_dir", help="Directory containing config.json")
    parser.add_argument("--user_id", type=int, help="Tautulli user ID")
    parser.add_argument("--user_email", help="Email address of the Plex user")
    parser.add_argument("--session_id", help="Tautulli session ID for the user")
    parser.add_argument(
        "--remaining_duration_sec",
        type=int,
        help="Remaining duration of media being watched (in seconds)",
    )
    parser.add_argument(
        "--cutoff_message", help="Message to display when killing session"
    )

    return parser.parse_args()


async def load_config(config_dir: str):
    config_file = Path(config_dir) / "config.json"
    try:
        async with AIOFile(config_file, "r") as f:
            return json.loads(await f.read())
    except FileNotFoundError:
        print(f"Config file not found at {config_file}.")
        return {}


async def save_config(config_dir: str, config: Dict[str, Any]):
    config_file = Path(config_dir) / "config.json"
    async with AIOFile(config_file, "w") as f:
        await f.write(json.dumps(config, indent=4))


async def refresh_patron_token(
    session: httpx.AsyncClient, config_dir: str, config: Dict[str, Any]
) -> str:
    """Refresh the Patreon access token using the refresh token."""
    if not config.get("patreon_refresh_token"):
        raise ValueError("No refresh token found in config.")
    if not config.get("patreon_client_id"):
        raise ValueError("No client ID found in config.")
    if not config.get("patreon_client_secret"):
        raise ValueError("No client secret found in config.")
    expires_at = (
        datetime.fromisoformat(
            config.get("patreon_expires_at", datetime.now(timezone.utc))
        )
        if config.get("patreon_expires_at")
        else None
    )
    if expires_at and datetime.now(timezone.utc) < (expires_at - timedelta(minutes=1)):
        print("Token is still valid. No need to refresh.")
        return config["patreon_access_token"]

    print("Token expired or not found. Refreshing...")
    # trunk-ignore(bandit/B105)
    token_url = "https://www.patreon.com/api/oauth2/token"
    data = {
        "grant_type": "refresh_token",
        "refresh_token": config["patreon_refresh_token"],
        "client_id": config["patreon_client_id"],
        "client_secret": config["patreon_client_secret"],
    }
    response = await session.post(token_url, data=data)
    response.raise_for_status()
    json_data = response.json()

    config["patreon_access_token"] = json_data.get("access_token", None)
    config["patreon_refresh_token"] = json_data.get("refresh_token", None)
    expires_in = json_data.get("expires_in", 0)
    config["patreon_expires_at"] = (
        datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    ).isoformat()
    await save_config(config_dir, config)
    return response.json()["access_token"]


async def is_active_patron(
    session: httpx.AsyncClient, access_token: str, user_email: str
) -> bool:
    """Check if the user is an active patron."""
    headers = {"Authorization": f"Bearer {access_token}"}

    # Request all memberships (you may need to paginate if you have too many donors, you popular beast)
    url = "https://www.patreon.com/api/oauth2/v2/campaigns/2900318/members"
    r = await session.get(
        url,
        headers=headers,
        params={
            "include": "user",
            "fields[user]": "email",
            "fields[member]": "patron_status,email",
        },
    )
    r.raise_for_status()
    data = r.json()

    for member in data["data"]:
        # member["relationships"]["user"]["data"]["id"]
        email = member["attributes"].get("email")
        status = member["attributes"].get("patron_status")

        if email and email.lower() == user_email.lower() and status == "active_patron":
            return True

    return False


async def get_weekly_watch_time(
    session: httpx.AsyncClient, tautulli_url: str, api_key: str, user_id: int
) -> int:
    """Retrieve the total watch time for the current week in seconds."""
    now = datetime.now(timezone.utc)
    days_since_sunday = (now.weekday() + 1) % 7
    start_of_week = now - timedelta(
        days=days_since_sunday,
        hours=now.hour,
        minutes=now.minute,
        seconds=now.second,
        microseconds=now.microsecond,
    )

    params = {
        "apikey": api_key,
        "cmd": "get_history",
        "user_id": user_id,
        "order_column": "date",
        "order_dir": "desc",
        "length": 1000,
        "watched_status": 1,
    }
    r = await session.get(f"{tautulli_url}{TAUTULLI_ENDPOINT}", params=params)
    r.raise_for_status()
    history = r.json()["response"]["data"]["data"]
    return sum(
        int(item.get("play_duration", 0))
        for item in history
        if datetime.fromtimestamp(item["date"], tz=timezone.utc) >= start_of_week
    )


async def get_current_sessions(
    session: httpx.AsyncClient, tautulli_url: str, api_key: str
) -> List[Dict[str, Any]]:
    params = {"apikey": api_key, "cmd": "get_activity"}
    r = await session.get(f"{tautulli_url}{TAUTULLI_ENDPOINT}", params=params)
    r.raise_for_status()
    return r.json()["response"]["data"]["sessions"]


async def terminate_session(
    session: httpx.AsyncClient,
    tautulli_url: str,
    api_key: str,
    session_id: int,
    message: str,
) -> None:
    """Terminate plex session with prejustice."""
    params = {
        "apikey": api_key,
        "cmd": "terminate_session",
        "session_id": session_id,
        "message": message,
        "reason": message,
    }
    r = await session.get(f"{tautulli_url}{TAUTULLI_ENDPOINT}", params=params)
    r.raise_for_status()


async def enforce_quota(
    config_dir: str,
    user_id,
    user_email: str,
    session_id: int,
    media_remaining: int,
    cutoff_message: str,
    quota_seconds: int = 10800,  # 3 hours
) -> None:
    """Enforce the weekly screen time quota for a user."""
    if not user_email:
        print("No user email provided")
        exit(1)
    if not user_id:
        print("No user ID provided")
        exit(1)
    if not session_id:
        print("No session ID provided")
        exit(1)
    if not media_remaining:
        print("No media remaining provided")
        exit(1)
    if not cutoff_message:
        print("No cutoff message provided")
        exit(1)
    if not quota_seconds:
        print("No quota seconds provided")
        exit(1)
    if not config_dir:
        print("No config directory provided")
        exit(1)
    if not Path(config_dir).exists():
        print(f"Config directory {config_dir} does not exist.")
        exit(1)
    if not Path(config_dir).is_dir():
        print(f"Config directory {config_dir} is not a directory.")
        exit(1)
    if not Path(config_dir, "config.json").exists():
        print(f"Config file {config_dir}/config.json does not exist.")
        exit(1)
    try:
        config = await load_config(config_dir)
        async with httpx.AsyncClient() as client:
            patreon_token = await refresh_patron_token(client, config_dir, config)

            if await is_active_patron(client, patreon_token, user_email):
                print("User is a Patron. Let them feast.")
                return

            watched_seconds = await get_weekly_watch_time(
                client, config["tautulli_url"], config["tautulli_api_key"], user_id
            )

            remaining_quota = quota_seconds - watched_seconds

            if remaining_quota <= 0:
                print("Quota already exceeded. Terminating.")
                await terminate_session(
                    client,
                    config["tautulli_url"],
                    config["tautulli_api_key"],
                    session_id,
                    cutoff_message,
                )
            elif media_remaining > remaining_quota:
                print(
                    f"Scheduling kill in {remaining_quota} seconds (media is too long)."
                )
                asyncio.create_task(
                    delayed_kill(
                        client,
                        config["tautulli_url"],
                        config["tautulli_api_key"],
                        session_id,
                        cutoff_message,
                        remaining_quota,
                    )
                )
            else:
                print("User is within quota. Proceeding without enforcement.")
    except Exception as e:
        print(f"An error occurred: {e}")
        exit(1)


async def delayed_kill(client, tautulli_url, api_key, session_id, message, delay):
    check_interval = 300  # seconds (5 minutes)
    time_remaining = delay

    print(
        f"Scheduled termination in {delay} seconds. Will check every 5 minutes for session presence."
    )

    while time_remaining > 0:
        print(f"Checking if session {session_id} is still active...")
        await asyncio.sleep(min(check_interval, time_remaining))
        time_remaining -= check_interval

        # Check if session is still active
        params = {"apikey": api_key, "cmd": "get_activity"}
        try:
            r = await client.get(f"{tautulli_url}{TAUTULLI_ENDPOINT}", params=params)
            r.raise_for_status()
            sessions = r.json()["response"]["data"]["sessions"]
            active_session_ids = [s["session_id"] for s in sessions]

            if session_id not in active_session_ids:
                print(
                    f"Session {session_id} is no longer active. Canceling scheduled kill."
                )
                return
        except Exception as e:
            print(
                f"Error while checking session activity: {e}. Continuing countdown just in case."
            )

    print(f"Time’s up. Executing final blow on session {session_id}.")
    await terminate_session(client, tautulli_url, api_key, session_id, message)


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(
        enforce_quota(
            config_dir=args.config_dir,
            user_id=args.user_id,
            user_email=args.user_email,
            session_id=args.session_id,
            media_remaining=args.remaining_duration_sec,
            cutoff_message=args.cutoff_message,
        )
    )
