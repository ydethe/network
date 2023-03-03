import os
import unittest

from network.exceptions import *


def failing_computation(arg):
    raise SampleException


class TestExceptions(unittest.TestCase):
    def test_sample(self):
        self.assertRaises(SampleException, failing_computation, "foo")


if __name__ == "__main__":
    unittest.main()
