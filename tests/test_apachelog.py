import unittest

import apachelog


class ApacheLogParserTests(unittest.TestCase):
    def setUp(self):
        self.format = apachelog.formats["extended"]
        self.parser = apachelog.parser(self.format)

    def test_parses_combined_log_line(self):
        line = (
            '212.74.15.68 - - [23/Jan/2004:11:36:20 +0000] '
            '"GET /images/previous.png HTTP/1.1" 200 2607 '
            '"http://example.com/" "Test Browser/1.0"'
        )

        self.assertEqual(
            self.parser.parse(line),
            {
                "%h": "212.74.15.68",
                "%l": "-",
                "%u": "-",
                "%t": "[23/Jan/2004:11:36:20 +0000]",
                "%r": "GET /images/previous.png HTTP/1.1",
                "%>s": "200",
                "%b": "2607",
                "%{Referer}i": "http://example.com/",
                "%{User-agent}i": "Test Browser/1.0",
            },
        )

    def test_parses_escaped_quotes_in_request(self):
        line = (
            r'212.74.15.68 - - [23/Jan/2004:11:36:20 +0000] '
            r'"GET /path=\"value\" HTTP/1.1" 200 12 "-" "Browser"'
        )

        self.assertEqual(
            self.parser.parse(line)["%r"],
            r'GET /path=\"value\" HTTP/1.1',
        )

    def test_rejects_unmatching_line(self):
        with self.assertRaises(apachelog.ApacheLogParserError):
            self.parser.parse("not an access log line")

    def test_names_and_pattern_are_available(self):
        self.assertEqual(
            self.parser.names(),
            [
                "%h",
                "%l",
                "%u",
                "%t",
                "%r",
                "%>s",
                "%b",
                "%{Referer}i",
                "%{User-agent}i",
            ],
        )
        self.assertTrue(self.parser.pattern().startswith("^"))
        self.assertTrue(self.parser.pattern().endswith("$"))

    def test_parse_date(self):
        self.assertEqual(
            apachelog.parse_date("[05/Dec/2006:10:51:44 +0000]"),
            ("20061205105144", "+0000"),
        )

    def test_custom_alias(self):
        class AliasedParser(apachelog.parser):
            def alias(self, name):
                return name.lstrip("%")

        parser = AliasedParser("%h")
        self.assertEqual(parser.parse("192.0.2.1"), {"h": "192.0.2.1"})


if __name__ == "__main__":
    unittest.main()
