#
# This is a GNU-make Makefile for Wsock-Trace's './doc/wsock_trace.chm'
#
LOG_FILE = doxygen.log

DOC_GENERATED    = wsock_trace.chm wsock_trace.chw doxygen.log
OUTPUT_GENERATED = $(addprefix ./output/, \
                     *.css *.html *.js *.png *.map *.md5 index.{hhc,hhk,hhp} )

all: wsock_trace.chm

wsock_trace.chm: Makefile wsock_trace.Doxyfile main_page.dox wsock_trace.css ../src/*.[ch]
	rm -f output/msc*.png                      ; \
	doxygen wsock_trace.Doxyfile > $(LOG_FILE) ; \
	cd output                                  ; \
	hhc index.hhp                              ; \
	mv -f wsock_trace.chm ..
	@echo 'Doxygen done. Look in "$(LOG_FILE)" for messages.'

clean:
	rm -f $(OUTPUT_GENERATED)
	rm -f $(DOC_GENERATED)
	- rmdir output
	@echo '"clean" done.'
