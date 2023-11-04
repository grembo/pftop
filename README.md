PFTOP(8) - FreeBSD System Manager's Manual

# NAME

**pftop** - display pf states

# SYNOPSIS

**pftop**
\[**-abDhir**]
\[**-c**&nbsp;*cache*]
\[**-d**&nbsp;*count*]
\[**-f**&nbsp;*filter*]
\[**-o**&nbsp;*field*]
\[**-s**&nbsp;*time*]
\[**-v**&nbsp;*view*]
\[**-w**&nbsp;*width*]
\[*number*]

# DESCRIPTION

**pftop**
displays the active packetfilter states and rules, and periodically
updates this information.
If standard output is an intelligent terminal (see below) then as
many states as will fit on the terminal screen are displayed by
default.
Otherwise, a good number of them are shown (around 20).
If
*number*
is given, then the top
*number*
states will be displayed instead of the default.
The displayed states are filtered according to the
*filter*
specification.

The options are as follows:

**-a**

> List all states.
> This option is only valid in batch mode.

**-b**

> Use
> *batch*
> mode.
> In this mode, all input from the terminal is ignored.
> Interrupt characters (such as
> '`^C`'
> and
> '`^\`')
> still have an effect.
> This is the default on a dumb terminal, or when the output is not
> a terminal.

**-c** *cache*

	Store
	*cache*
	number of states for rate calculation.

**-d** *count*

	Update the display
	*count*
	times, then exit.
	For dumb terminals, the default is 1.

**-D**

	This option is intended for debugging the filter. The filter code and
	resulting states are displayed in raw form. The binary state data is
	also dumped to a file named
	*state.dmp*
	in the current directory.

**-f** *filter*

	This option specifies the filter that is applied to the states.
	The filter specification is based on the
	*tcpdump*
	format. See the section on
	*STATE FILTERING*
	for details on the filter syntax.

**-i**

	Use
	*interactive*
	mode.
	In this mode, any input is immediately read for processing.
	See the section on
	*INTERACTIVE MODE*
	for an explanation of which keys perform what functions.
	After the command is processed, the screen will be updated immediately.
	This mode is the default when standard output is an intelligent
	terminal.

**-o** *field*

	Sort the process display area using the specified field as the
	primary key.
	Accepted field arguments are:
	*age*,
	*bytes*,
	*dest*,
	*dport*,
	*exp*,
	*none*,
	*peak*,
	*pkt*,
	*rate*,
	*size*,
	*sport*,
	and
	*src*.

**-r**

	Reverse the sort order.

**-s** *time*

	Set the delay between display updates to
	*time*
	seconds.
	The default delay is 5 seconds.

**-v** *view*

	Select the initial arrangement of the columns. Available
	views are:
	*default*,
	*long*,
	*state*,
	*time*,
	*size*,
	*rules*,
	*label*,
	and
	*speed*.
	The
	*rule*
	and
	*label*
	views display rules, while the other views display states.

**-w** *width*

	Set the width of the display for batch mode.
	The default width is 80.

# INTERACTIVE MODE

When
**pftop**
is running in
*interactive mode*,
it reads commands from the terminal and acts upon them accordingly.
In this mode, the terminal is put in
`CBREAK`,
so that a character will be processed as soon as it is typed.
The command will be processed and the display will be updated
immediately thereafter (reflecting any changes that the command may
have triggered).
If a key is pressed while
**pftop**
is in the middle of updating the display, it will finish the update
and then process the command.
These commands are currently recognized:

c

	Enable disable state caching (enabled by default).

f

	Set the state filter expression.

h,?

	Display a summary of the commands (help screen).

n

	Set number of lines to display.

o

	Select next sorting Order.

p

	Pause/resume display updates.

q

	Quit
	**pftop**.

r

	Reverse current sorting order.

s

	Set display update interval in Seconds.

v

	Select next View.

0-7

	Select one of the views directly.

Cursor

	Scroll display (up/down), and switch views (left/right).
	Most of the emacs/mg motion keys work as well.

SPACE

	Update display immediately.

CTRL-L

	Refresh display.

CTRL-G

	Clear command entry line.

The following keys are shortcuts for sorting
the display:

A

	Sort states by Age.

B

	Sort states by number of Bytes.

D

	Sort by Destination port.

E

	Sort states by Expiry time.

F

	Sort by source address (From).

K

	Sort by peaK speed when caching is enabled.

N

	No ordering.

P

	Sort states by the number of Packets.

R

	Sort by instantaneous speed (Rate) when caching is enabled.

S

	Sort by Source port.

T

	Sort by destination address (To).

# STATE FILTERING

The expression
*filter*
selects which states will be displayed. It is based on
the
*tcpdump*
filtering language. The following is based on the
*tcpdump*
manual page, modified for state filtering.

The
*filter*
expression consists of one or more primitives.
Primitives usually consist of an
*id*
(name or number)
preceded by one or more qualifiers.
There are three different kinds of qualifiers:

*type*

	Specify which kind of address component the
	*id*
	name or number refers to.
	Possible types are
	**host**,
	**net**
	and
	**port**.
	If there is no type qualifier,
	**host**
	is assumed.

*dir*

	Specify a the address component (src, dest, gateway) that
	*id*
	applies. Possible directions are
	**src**,
	**dst**,
	**gw**,
	**src or dst**,
	**src and dst**.
	If there is no
	*dir*
	qualifier,
	**src or dst or gw**
	is assumed.

*proto*

	Restrict the match to a particular protocol.
	Possible protocols are:
	**ah**,
	**carp**,
	**esp**,
	**icmp**,
	**ip**,
	**ip6**,
	**pfsync**,
	**tcp**,
	and
	**udp**.
	If there is no protocol qualifier,
	all protocols consistent with the type are assumed.

In addition to the above, there are some special primitive
keywords that don't follow the pattern and arithmetic expressions.
All of these are described below.

More complex filter expressions are built up by using the words
**and**,
**or**,
and
**not**
to combine primitives.

Allowable primitives are:

**dst host** *host*

	True if the IP destination field of the state is
	*host*,
	which may be either an address or a name.

**gw host** *host*

	True if the IP gateway field of the state is
	*host*.

**src host** *host*

	True if the IP source field of the state is
	*host*.

**host** *host*

	True if either the IP source or destination or gateway of the
	state is
	*host*.
	If
	*host*
	is a name with multiple IP addresses, each address will be checked for a match.

**dst net** *net*

	True if the IP destination address of the state has a network number of
	*net*.
	*net*
	may be either a name from
	*/etc/networks*
	or a network number (see
	networks(5)
	for details).

**gw net** *net*

	True if the IP gateway address of the state has a network number of
	*net*.

**src net** *net*

	True if the IP source address of the state has a network number of
	*net*.

**net** *net*

	True if either the IP source, destination or gateway address of
	the state has a network number of
	*net*.

	Any of the above
	*host*
	or
	*net*
	expressions can be prepended with the keywords,
	**ip**,
	or
	**ip6**.

**dst port** *port*

	True if the packet is IP/TCP or IP/UDP and has a destination port value of
	*port*.
	The
	*port*
	can be a number or name from
	services(5)
	(see
	tcp(4)
	and
	udp(4)).
	If a name is used, both the port number and protocol are checked.
	If a number or ambiguous name is used, only the port number is checked;

**port** *port*

	True if either the source, destination or gateway port of the state is
	*port*.

	Any of the above port expressions can be prepended with the keywords
	**tcp**
	or
	**udp**,
	as in:

		**tcp src port** *port*

	which matches only TCP states whose source port is
	*port*.

**inbound**,
**in**

	True if the state has an inbound direction.

**outbound**,
**out**

	True if the state has an outbound direction.

**proto** *proto*

	True if the IP protocol type of the state is
	*proto*.
	*proto*
	can be a number or name from
	protocols(5),
	such as
	**icmp**,
	**udp**,
	or
	**tcp**.

**rnr** *num*

	True if the state was generated with the rule number
	in the main ruleset.

**ah**,
**carp**
**esp**,
**icmp**,
**pfsync**,
**tcp**,
**udp**

	Abbreviations for:
	**proto** *p*
	where
	*p*
	is one of the above protocols.

*expr relop expr*

	True if the relation holds, where
	*relop*
	is one of
	'`>`',
	'`<`',
	'`>=`',
	'`<=`',
	'`=`',
	'`!=`',
	and
	*expr*
	is an arithmetic expression composed of integer constants
	(expressed in standard C syntax),
	the normal binary operators
	('`+`',
	'`-`',
	'`*`',
	'`/`',
	'`&`',
	'`|`'),
	a length operator, and special state data accessors.

	The following expressions can be used to access numerical
	fields inside a state:
	**inp**,
	and
	**outp**
	return input and output packet counts.
	**inb**,
	and
	**outb**
	is for input and output bytes transferred through the state.
	**age**
	is the seconds since the state is created, and
	**exp**
	is the number of seconds left before the state expires.

Primitives may be combined using a parenthesized group of primitives and
operators.
Allowable primitives and operators are:

	Negation
	("**!**"
	or
	"**not**")

	Concatenation
	("**&&**"
	or
	"**and**")

	Alternation
	("**||**"
	or
	"**or**")

Negation has highest precedence.
Alternation and concatenation have equal precedence and associate left to right.

Expression arguments must be passed to
**pftop**
as a single argument. Since the expression
usually contains shell metacharacters,
it should be placed in quotes.

# SEE ALSO

pf(4),
pfctl(8),
tcpdump(8)

# AUTHORS

Can Erkin Acar

FreeBSD 13.2-RELEASE-p2 - March 22, 2002
