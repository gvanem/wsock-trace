#
# This is a GNU-make Makefile for Wsock-Trace's './doc'
#
THIS_DIR = $(dir $(realpath Makefile))

DOC_GENERATED    = Wsock-Trace.chm Wsock-Trace.chw doxygen.log
OUTPUT_GENERATED = $(addprefix ./output/, \
                     *.css *.html *.js *.png *.map *.md5 index.{hhc,hhk,hhp} )

all: Wsock-Trace.chm

Wsock-Trace.chm: Makefile Wsock-Trace.Doxyfile main_page.dox Wsock-Trace.css ../src/*.[ch]
	rm -f output/msc*.png                      ; \
	doxygen Wsock-Trace.Doxyfile > doxygen.log ; \
	cd output                                  ; \
	hhc index.hhp                              ; \
	mv -f Wsock-Trace.chm ..
	@echo 'Doxygen done. Look in "$(realpath doxygen.log)" for messages.'

clean:
	rm -f $(OUTPUT_GENERATED)
	rm -f $(DOC_GENERATED)
	-rmdir output
	@echo '"clean" done.'
