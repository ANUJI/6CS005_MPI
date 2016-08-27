#
#
# To compile code in all subdirectories type make:
#
#    $ make
#
# To run all unit tests, type:
#
#    $ make test
#
# To remove all generated files, type:
#
#    $ make clean
#
# - Sarah Mount, September 2014
#

SUBDIRS = serial

all:
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $${dir} $@ || exit $$?; \
	done

test:
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $${dir} test || exit $$?; \
	done

clean:
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $${dir} clean || exit $$?; \
	done
