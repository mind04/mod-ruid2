#!/usr/bin/make -f <
#
# Copyright (C) 2013 Bertrand Jacquin <beber@meleeweb.net>

NAME	= mod_ruid2
VERSION = $(shell git describe --tags --dirty=-dev 2> /dev/null)

SRC	= \
	mod_ruid2.c

DOC_FILES	= \
	README \
	ruid2.conf

EXTRA_FILES	= \
	LICENSE \
	Makefile

PKG_CONFIG	?= pkg-config

APR_CFLAGS	= \
	$(shell $(PKG_CONFIG) --cflags apr-1)

APR_LDFLAGS	= \
	$(shell $(PKG_CONFIG) --libs apr-1)

HTTPD_CFLAGS	= \
	-I/usr/include/apache2

CAP_LDFLAGS	= \
	-lcap

CFLAGS	?= \
	-W -Wall

SPEC_CFLAGS	= \
	-DMODULE_NAME='"$(NAME)"'	\
	-DMODULE_VERSION='"$(VERSION)"'	\
	-fPIC \
	$(HTTPD_CFLAGS) \
	$(APR_CFLAGS) \
	$(CAP_CFLAGS)

SPEC_LDFLAGS	= \
	$(HTTPD_LDFLAGS) \
	$(APR_LDFLAGS) \
	$(CAP_LDFLAGS)

ifdef DEBUG
SPEC_CFLAGS +=\
	-DDEBUG \
	-g -ggdb
endif # DEBUG

CC	?= cc

STRIP	?= strip
STRIP_FLAGS	?= --strip-unneeded -R .comment -R .GCC.command.line -R .note.gnu.build-id

INSTALL	?= install

RM	?= rm -f

TAR	= tar
XZ	= xz

DESTDIR	?=
PREFIX	?= /usr/local
MODDIR	?= $(PREFIX)/lib/apache2/modules
DOCDIR	?= $(PREFIX)/share/doc/$(NAME)

ifeq ($(V),)
 Q		= @

 quiet_cmd	= @printf "  %-6s %s\n" "$(1)" "$(2)";
endif	# $(V)

all:	shared

shared:	$(NAME).so
dist:	$(NAME)-$(VERSION).txz

# Build rules
%.o:	%.c
	$(call quiet_cmd,CC,$@)
	$(Q)$(CC) -c $(SPEC_CFLAGS) $(CFLAGS) -o $@ $<

$(NAME).so:	$(SRC:c=o)
	$(call quiet_cmd,CC,$@)
	$(Q)$(CC) -shared -o $@ $^ $(SPEC_LDFLAGS) $(LDFLAGS)

strip:	$(NAME).so
	$(call quiet_cmd,STRIP,$<)
	$(Q)$(STRIP) $(STRIP_FLAGS) $<

# Archiving rules
$(NAME)-$(VERSION).tar:	$(SRC) $(EXTRA_FILES) $(DOC_FILES)
	$(call quiet_cmd,TAR,$@)
	$(Q)$(TAR) cf $@ \
		--transform "s,^,$(NAME)-$(VERSION)/," \
		--force-local --numeric-owner \
		$^

%.txz: 	%.tar
	$(call quiet_cmd,XZ,$@)
	$(Q)$(XZ) -c > $@ < $<

# Install rules
install:	\
	$(DESTDIR)$(MODDIR)/$(NAME).so \
	$(addprefix $(DESTDIR)$(DOCDIR)/,$(DOC_FILES))

$(DESTDIR)$(MODDIR)/$(NAME).so:	$(NAME).so
	$(call quiet_cmd,INSTALL,$@)
	$(Q)$(INSTALL) -D -m 444 $< $@

$(DESTDIR)$(DOCDIR)/%:	%
	$(call quiet_cmd,INSTALL,$@)
	$(Q)$(INSTALL) -D -m 444 $< $@

# Cleanup rules
clean:
	$(call quiet_cmd,RM,$(SRC:c=o))
	$(Q)$(RM) $(SRC:c=o)
	$(call quiet_cmd,RM,$(NAME).so)
	$(Q)$(RM) $(NAME).so

distclean: clean
	$(call quiet_cmd,RM,$(NAME)-$(VERSION).tar)
	$(Q)$(RM) $(NAME)-$(VERSION).tar
	$(call quiet_cmd,RM,$(NAME)-$(VERSION).txz)
	$(Q)$(RM) $(NAME)-$(VERSION).txz

.PHONY:	strip
