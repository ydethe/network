"""

.. include:: ../README.md

# Testing

## Run the tests

To run tests, just run:

    pdm test

## Baseline images generation

If needed (for example, a new test with its associated baseline image), we might have to regenerate the baseline images. In this case, run:

    pdm baseline

## Test reports

[See test report](../tests/report.html)

[See test results](../tests/results/fig_comparison.html)

[See coverage](../coverage/index.html)

# Class diagram

![classes](./classes.png "Class diagram")

"""
import os
import logging

# création de l'objet logger qui va nous servir à écrire dans les logs
logger = logging.getLogger(f"{__package__}_logger")
logger.setLevel(os.environ.get("LOGLEVEL", "INFO").upper())
