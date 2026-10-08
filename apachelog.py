#!/usr/bin/env python
"""Parse Apache access log lines using a configurable log format."""

__version__ = "1.1.0"
__license__ = """Released under the same terms as Perl.
See: http://dev.perl.org/licenses/
"""
__author__ = "Harry Fuecks <hfuecks@gmail.com>"
__contributors__ = [
    "Peter Hickman <peterhi@ntlworld.com>",
    "Loic Dachary <loic@dachary.org>"
    ]
    
import re
from datetime import datetime
from typing import Dict, List, Tuple

class ApacheLogParserError(Exception):
    pass

class parser:
    
    def __init__(self, format: str) -> None:
        """
        Takes the log format from an Apache configuration file.

        Best just copy and paste directly from the .conf file
        and pass using a Python raw string e.g.
        
        format = r'%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'
        p = apachelog.parser(format)
        """
        self._names = []
        self._regex = None
        self._pattern = ''
        self._parse_format(format)
    
    def _parse_format(self, format: str) -> None:
        """
        Converts whitespace-delimited format fields to a regular expression
        and extracts their names.

        Apache directives are treated as opaque fields except for the
        directives that require special matching: %t and %U.
        """
        subpatterns = []
        self._names = []

        elements = []
        element = []
        quoted = False
        brace_depth = 0
        index = 0
        while index < len(format):
            char = format[index]
            if format.startswith(r'\"', index):
                quoted = not quoted
                element.extend(('\\', '"'))
                index += 2
                continue
            if char == '{':
                brace_depth += 1
            elif char == '}':
                brace_depth -= 1
                if brace_depth < 0:
                    raise ApacheLogParserError("Invalid format: unmatched '}'")

            if char in ' \t' and not quoted and brace_depth == 0:
                if element:
                    elements.append(''.join(element))
                    element = []
            else:
                element.append(char)
            index += 1

        if quoted:
            raise ApacheLogParserError("Invalid format: unterminated quoted field")
        if brace_depth:
            raise ApacheLogParserError("Invalid format: unterminated directive parameter")
        if element:
            elements.append(''.join(element))
        if not elements:
            raise ApacheLogParserError("Invalid format: no fields specified")

        directive = re.compile(
            r"%(?:[<>])?(?:\{[^{}]+\}(?:\^[A-Za-z]{2}|[A-Za-z])|[A-Za-z])"
        )
        quoted_value = r'"([^"\\]*(?:\\.[^"\\]*)*)"'

        for element in elements:
            hasquotes = element.startswith(r'\"') and element.endswith(r'\"')
            if element.startswith(r'\"') != element.endswith(r'\"'):
                raise ApacheLogParserError("Invalid format: mismatched quotes")
            if hasquotes:
                element = element[2:-2]

            if element.startswith('%') and directive.fullmatch(element) is None:
                raise ApacheLogParserError(
                    "Invalid Apache LogFormat directive: {!r}".format(element)
                )

            self._names.append(self.alias(element))

            subpattern = r'(\S*)'

            if hasquotes:
                subpattern = quoted_value
            elif element == '%t':
                subpattern = r'(\[[^\]]+\])'
            elif element == '%U':
                subpattern = '(.+?)'

            subpatterns.append(subpattern)

        self._pattern = '^' + ' '.join(subpatterns) + '$'
        try:
            self._regex = re.compile(self._pattern)
        except re.error as error:
            raise ApacheLogParserError(error) from error

    def parse(self, line: str) -> Dict[str, str]:
        """
        Parses a single line from the log file and returns
        a dictionary of it's contents.

        Raises and exception if it couldn't parse the line
        """
        line = line.strip()
        match = self._regex.match(line)
        
        if match:
            data = {}
            for k, v in zip(self._names, match.groups()):
                data[k] = v
            return data
        
        raise ApacheLogParserError("Unable to parse: %s with the %s regular expression" % ( line, self._pattern ) )

    def alias(self, name: str) -> str:
        """
        Override / replace this method if you want to map format
        field names to something else. This method is called
        when the parser is constructed, not when actually parsing
        a log file
        
        Takes and returns a string fieldname
        """
        return name

    def pattern(self) -> str:
        """
        Returns the compound regular expression the parser extracted
        from the input format (a string)
        """
        return self._pattern

    def names(self) -> List[str]:
        """
        Returns the field names the parser extracted from the
        input format (a list)
        """
        return self._names

months = {
    'Jan':'01',
    'Feb':'02',
    'Mar':'03',
    'Apr':'04',
    'May':'05',
    'Jun':'06',
    'Jul':'07',
    'Aug':'08',
    'Sep':'09',
    'Oct':'10',
    'Nov':'11',
    'Dec':'12'
    }

def parse_date(date: str) -> Tuple[str, str]:
    """
    Takes a date in the format: [05/Dec/2006:10:51:44 +0000]
    (including square brackets) and returns a two element
    tuple containing first a timestamp of the form
    YYYYMMDDHH24IISS e.g. 20061205105144 and second the
    timezone offset as is e.g.;

    parse_date('[05/Dec/2006:10:51:44 +0000]')  
    >> ('20061205105144', '+0000')

    It does not attempt to adjust the timestamp according
    to the timezone - this is your problem.
    """
    match = re.fullmatch(
        r"\[([0-9]{2})/([A-Za-z]{3})/([0-9]{4}):"
        r"([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-][0-9]{4})\]",
        date,
    )
    if match is None:
        raise ValueError("Invalid Apache log date: {!r}".format(date))

    day, month_name, year, hour, minute, second, timezone = match.groups()
    try:
        month = months[month_name]
        offset_hour = int(timezone[1:3])
        offset_minute = int(timezone[3:5])
        if offset_hour > 23 or offset_minute > 59:
            raise ValueError("Invalid timezone offset")
        datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
        )
    except (KeyError, ValueError) as error:
        raise ValueError("Invalid Apache log date: {!r}".format(date)) from error

    return "{}{}{}{}{}{}".format(year, month, day, hour, minute, second), timezone


"""
Frequenty used log formats stored here
"""
formats = {
    # Common Log Format (CLF)
    'common':r'%h %l %u %t \"%r\" %>s %b',

    # Common Log Format with Virtual Host
    'vhcommon':r'%v %h %l %u %t \"%r\" %>s %b',

    # NCSA extended/combined log format
    'extended':r'%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"',
    }
