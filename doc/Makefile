#
# This is a GNU-make Makefile for Wsock-Trace's './doc/wsock_trace.chm'
#
all: wsock_trace.chm

wsock_trace.chm: Makefile wsock_trace.Doxyfile main_page.dox wsock_trace.css ../src/*.[ch]
	export LIBRARY_PATH= ; export MINGW32=     ; \
	rm -f output/msc*.png                      ; \
	doxygen wsock_trace.Doxyfile > doxygen.log ; \
	cd output                                  ; \
	hhc index.hhp                              ; \
	mv -f wsock_trace.chm ..
	@echo 'Doxygen done. Look in "doxygen.log" for details.'

clean:
	rm -fr output
	rm -f wsock_trace.{chm,chw} doxygen.log
	@echo '"$@" done.'
