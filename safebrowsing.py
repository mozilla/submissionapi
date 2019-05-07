#!/usr/bin/env python3
import argparse
import logging
import requests
import json
from yaml import Loader, load, dump
from sys import argv, stderr
from os import environ, fsync, stat, rename
from logging.handlers import SysLogHandler


def setup_logging(stream=stderr, level=logging.INFO):
    formatstr = (
        "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    )
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=stream)
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    return logger


def init_config():
    config = {}

    with open(argv[0].replace(".py", ".yml"), "r") as configyaml:
        cf = load(configyaml, Loader=Loader)

    config["debug"] = cf.get("debug", False)
    config["apiurl"] = cf.get("apiurl", "<APIURL>")
    config["apikey"] = cf.get("apikey", "<SECRET>")
    config["urllist"] = cf.get("urllist", "urllist.txt")

    return config


def submit_report(config, rl):
    s = requests.Session()

    apikey = {"key": config["apikey"]}

    for rep in rl:
        r = s.post(
            config["apiurl"],
            headers={"Content-Type": "application/json"},
            json=rep,
            params=apikey,
        )
        print(r)

        # req = requests.Request(
        #    "POST",
        #    config["apiurl"],
        #    headers={"Content-Type": "application/json"},
        #    json=rep,
        #    params=apikey,
        # )
        # p = req.prepare()
        # print(p.method, p.url, p.headers, p.body)

        # etags[c] = r.headers["ETag"]
        # if r.status_code == 304 and len(r.content) == 0:
        #    log.debug("No new data found, skipping update")
        # elif r.status_code != 304 and len(r.content) != 0:
        #    intel_save(config, c, r.content)
        # elif r.status_code == 304 and len(r.content) != 0:
        #    log.error("An impossible thing just happened")


def get_urls(config):
    urls = []

    try:
        with open(config["urllist"], "rb") as u:
            data = u.readlines()
        urls = [url.decode("UTF-8").strip() for url in data]
    except FileNotFoundError:
        log.error("Could not open {0}".format(config["urllist"]))

    return urls


def create_report(urls):
    rl = []

    for url in urls:
        rep = {}
        tr = {}
        ci = {}
        te = {}
        tl = {}

        tl["url"] = url

        # te["hash"]
        # te["digest"]
        te["url"] = url

        tr["threatTypes"] = ["MALWARE", "SOCIAL_ENGINEERING"]
        tr["threatEntryType"] = "URL"
        tr["threatEntry"] = te

        ci["clientId"] = "Mozilla-EIS-Python-Requests"
        ci["clientVersion"] = "1.0"

        rep["threatReport"] = tr
        rep["clientInfo"] = ci

        rl.append(rep)

    return rl


def main():
    urls = []
    rl = {}

    urls = get_urls(config)
    rl = create_report(urls)
    r = submit_report(config, rl)


if __name__ == "__main__":
    environ["TZ"] = "UTC"  # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Specify a configuration file")
    parser.add_argument("-d", "--debug", help="Print debug messages")
    args = parser.parse_args()

    config = init_config()

    if args.debug or config["debug"]:
        log = setup_logging(level=logging.DEBUG)
    else:
        log = setup_logging(level=logging.INFO)
    log.level = logging.DEBUG
    log.debug("Started and initialized")

    main()
