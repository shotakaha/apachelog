## Apache Access Log Parser

Simple parser to turn an Apache access_log file (or any other file conforming to the Common Log Format) into a usable dictionary of values.

(forked from the [apachelog](http://code.google.com/p/apachelog/) project on Google Code, which began as a Python port of Peter Hickman's [Apache::LogEntry Perl module](http://cpan.uwinnipeg.ca/~peterhi/Apache-LogRegex))

## Usage

Create the parser with the log format from your server's config file, then parse lines to get a dict corresponding to fields defined in the log format.

Example:

    import apachelog
    import sys

    # Format copied and pasted from Apache conf - use raw string + single quotes
    format = r'%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'

    parser = apachelog.parser(format)

    with open('/var/apache/access.log', encoding='utf-8') as logfile:
        for line in logfile:
            try:
                data = parser.parse(line)
            except apachelog.ApacheLogParserError as error:
                print("Unable to parse log line: {}".format(error), file=sys.stderr)


The return dictionary from the parse method depends on the input format.  For the above example, the returned dictionary would look like;

    {
    '%>s': '200',
    '%b': '2607',
    '%h': '212.74.15.68',
    '%l': '-',
    '%r': 'GET /images/previous.png HTTP/1.1',
    '%t': '[23/Jan/2004:11:36:20 +0000]',
    '%u': '-',
    '%{Referer}i': 'http://peterhi.dyndns.org/bandwidth/index.html',
    '%{User-Agent}i': 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) Gecko/20021202'
    }

...given an access log entry like (split across lines for formatting):

    212.74.15.68 - - [23/Jan/2004:11:36:20 +0000] "GET /images/previous.png HTTP/1.1"
        200 2607 "http://peterhi.dyndns.org/bandwidth/index.html"
        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) Gecko/20021202"

You can also re-map the field names by subclassing (or re-pointing) the `alias` method.

Generally you should be able to copy and paste the format string from your configuration file, but remember to place it in a raw string using single-quotes, so that backslashes are handled correctly.

## LogFormat support

Format fields are separated by spaces or tabs. Fields wrapped in escaped
double quotes and directive parameters in braces are kept together during
format parsing. Directives such as `%h`, `%>s`, and `%{Referer}i` are captured
as opaque fields; the parser does not check whether a directive is supported
by a particular Apache version or module. `%t` matches a bracketed timestamp,
and `%U` matches a non-empty URI path. Quoted fields are parsed as quoted
values and may contain escaped characters.

Malformed directives (for example, `%{Referer}`) and unmatched quotes or
braces raise `ApacheLogParserError` when the parser is created. Input lines
that do not match the configured format raise the same exception when parsed.

## Installation

Install the package with pip:

    python -m pip install .

Python 3.8 or newer is supported.

## Tests

Run the regression tests from the repository root:

    python -m unittest discover -s tests

## License

This project is licensed under the Artistic License.
