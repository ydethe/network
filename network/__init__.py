"""

.. include:: ../README.md

[comment]: # (The class diagram is as follows:)

[comment]: # (![classes](./classes.png "Class diagram"))

# Tests and coverage

## Running tests

To run tests and code coverage, run:

    pdm test

## Reports

Once the tests ran, the reports are generated. See the links below:

[See test report](../tests/report.html)

[See test results](../tests/results/fig_comparison.html)

[See coverage](../coverage/index.html)

# Building distribution

The following command builds a wheel file in the dist folder:

    pdm build

The following command builds the doc in build/htmldoc/benjamin_mp:

    pdm doc

"""
import os
import logging

from rich.logging import RichHandler


logger = logging.getLogger("network_logger")
logger.setLevel(os.environ.get("LOGLEVEL", "INFO").upper())

stream_handler = RichHandler()
logger.addHandler(stream_handler)
