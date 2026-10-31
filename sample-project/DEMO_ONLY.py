"""Deliberately unsafe example for STATIC SCANNING ONLY. Do not execute."""
import requests


def bad_example(url):
    return requests.get(url, verify=False)  # insecure TLS verification
