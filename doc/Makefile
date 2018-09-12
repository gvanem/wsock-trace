#
# This is a GNU-make Makefile for Wsock-Trace's './doc'
#
LOG_FILE = doxygen.log

DOC_GENERATED    = Wsock-Trace.chm Wsock-Trace.chw doxygen.log
OUTPUT_GENERATED = $(addprefix ./output/, \
                     *.css *.html *.js *.png *.map *.md5 index.{hhc,hhk,hhp} )

all: Wsock-Trace.chm

Wsock-Trace.chm: Makefile Wsock-Trace.Doxyfile main_page.dox Wsock-Trace.css ../src/*.[ch]
	rm -f output/msc*.png                      ; \
	doxygen Wsock-Trace.Doxyfile > $(LOG_FILE) ; \
	cd output                                  ; \
	hhc index.hhp                              ; \
	mv -f Wsock-Trace.chm ..
	@echo 'Doxygen done. Look in "$(LOG_FILE)" for messages.'

clean:
	rm -f $(OUTPUT_GENERATED)
	rm -f $(DOC_GENERATED)
	-rmdir output
	@echo '"clean" done.'
